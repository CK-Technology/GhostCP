use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    handlers::auth::Claims,
    models::{DnsZone, DnsRecord, CreateDnsZoneRequest, CreateDnsRecordRequest},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListDnsZonesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListDnsZonesResponse {
    pub zones: Vec<DnsZoneWithRecordCount>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DnsZoneWithRecordCount {
    // All DnsZone fields
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub dns_provider: String,
    pub provider_zone_id: Option<String>,
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: i64,
    pub refresh_interval: i32,
    pub retry_interval: i32,
    pub expire_interval: i32,
    pub minimum_ttl: i32,
    pub dnssec_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // Additional field
    pub records_count: i64,
}

pub async fn list_dns_zones(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListDnsZonesQuery>,
) -> ApiResult<Json<ListDnsZonesResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let zones = sqlx::query_as::<_, DnsZoneWithRecordCount>(
        r#"
        SELECT z.*, CAST(COUNT(r.id) AS BIGINT) AS records_count
        FROM dns_zones z
        LEFT JOIN dns_records r ON z.id = r.zone_id
        WHERE z.user_id = $1
        GROUP BY z.id
        ORDER BY z.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dns_zones WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListDnsZonesResponse {
        zones,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_dns_zone(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateDnsZoneRequest>,
) -> ApiResult<Json<DnsZone>> {
    let user_id = claims_user_id(&claims)?;
    // Validate DNS provider
    let dns_provider = payload.dns_provider.as_deref().unwrap_or("local");
    let provider = state.dns_providers.get(dns_provider)
        .ok_or_else(|| ApiError::BadRequest(format!("DNS provider '{}' not available", dns_provider)))?;

    // Create zone with DNS provider first
    let provider_zone = crate::drivers::dns::DnsZone {
        id: None,
        name: payload.domain.clone(),
        primary_ns: payload.primary_ns.clone().unwrap_or_else(|| "ns1.ghostcp.com".to_string()),
        admin_email: payload.admin_email.clone().unwrap_or_else(|| "admin@example.com".to_string()),
        serial: 1,
        refresh: 3600,
        retry: 1800,
        expire: 1209600,
        minimum: 86400,
        dnssec_enabled: payload.dnssec_enabled.unwrap_or(true),
    };

    let zone_info = provider.create_zone(&provider_zone).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    // Create zone in database
    let db_zone = sqlx::query_as::<_, DnsZone>(
        r#"
        INSERT INTO dns_zones (
            user_id, domain, primary_ns, admin_email, serial,
            refresh_interval, retry_interval, expire_interval, minimum_ttl,
            dns_provider, provider_zone_id, dnssec_enabled, template
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        ) RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.domain)
    .bind(&provider_zone.primary_ns)
    .bind(&provider_zone.admin_email)
    .bind(provider_zone.serial as i64)
    .bind(provider_zone.refresh as i32)
    .bind(provider_zone.retry as i32)
    .bind(provider_zone.expire as i32)
    .bind(provider_zone.minimum as i32)
    .bind(dns_provider)
    .bind(&zone_info.id)
    .bind(provider_zone.dnssec_enabled)
    .bind(payload.template.as_deref().unwrap_or("default"))
    .fetch_one(&state.db)
    .await?;

    Ok(Json(db_zone))
}

pub async fn get_dns_zone(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<DnsZone>> {
    let user_id = claims_user_id(&claims)?;
    let zone = ensure_zone_owner(&state, zone_id, user_id).await?;
    Ok(Json(zone))
}

pub async fn list_dns_records(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
    Query(params): Query<ListDnsRecordsQuery>,
) -> ApiResult<Json<ListDnsRecordsResponse>> {
    let user_id = claims_user_id(&claims)?;
    ensure_zone_owner(&state, zone_id, user_id).await?;

    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * limit;

    let records = sqlx::query_as::<_, DnsRecord>(
        r#"SELECT * FROM dns_records WHERE zone_id = $1 ORDER BY name, "type" LIMIT $2 OFFSET $3"#
    )
    .bind(zone_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dns_records WHERE zone_id = $1"
    )
    .bind(zone_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ListDnsRecordsResponse {
        records,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_dns_record(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
    Json(payload): Json<CreateDnsRecordRequest>,
) -> ApiResult<Json<DnsRecord>> {
    let user_id = claims_user_id(&claims)?;
    // Get the zone (scoped to the caller) to determine the DNS provider
    let zone = ensure_zone_owner(&state, zone_id, user_id).await?;

    // Get DNS provider
    let provider = state.dns_providers.get(&zone.dns_provider)
        .ok_or_else(|| ApiError::BadRequest(format!("DNS provider '{}' not available", zone.dns_provider)))?;

    // Create record with DNS provider
    let provider_record = crate::drivers::dns::DnsRecord {
        id: None,
        zone_id: zone.provider_zone_id.clone().unwrap_or_default(),
        name: payload.name.clone(),
        record_type: payload.record_type.clone(),
        content: payload.value.clone(),
        ttl: payload.ttl.unwrap_or(3600) as u32,
        priority: payload.priority.map(|p| p as u16),
        proxied: None,
    };

    let _record_id = provider.create_record(&provider_record).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    // Create record in database
    let db_record = sqlx::query_as::<_, DnsRecord>(
        r#"
        INSERT INTO dns_records (
            zone_id, name, "type", value, ttl, priority
        ) VALUES (
            $1, $2, $3, $4, $5, $6
        ) RETURNING *
        "#,
    )
    .bind(zone_id)
    .bind(&payload.name)
    .bind(&payload.record_type)
    .bind(&payload.value)
    .bind(payload.ttl.unwrap_or(3600))
    .bind(payload.priority.unwrap_or(0))
    .fetch_one(&state.db)
    .await?;

    Ok(Json(db_record))
}

#[derive(Debug, Deserialize)]
pub struct ListDnsRecordsQuery {
    pub record_type: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListDnsRecordsResponse {
    pub records: Vec<DnsRecord>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn sync_dns_zone(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let user_id = claims_user_id(&claims)?;
    let zone = ensure_zone_owner(&state, zone_id, user_id).await?;

    // Get DNS provider
    let provider = state.dns_providers.get(&zone.dns_provider)
        .ok_or_else(|| ApiError::BadRequest(format!("DNS provider '{}' not available", zone.dns_provider)))?;

    // Get records from provider
    let provider_zone_id = zone.provider_zone_id.clone().unwrap_or_default();
    let provider_records = provider.list_records(&provider_zone_id, None).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    // Update database with provider records
    // This is a simplified sync - in practice you'd want more sophisticated reconciliation
    sqlx::query("DELETE FROM dns_records WHERE zone_id = $1")
        .bind(zone_id)
        .execute(&state.db)
        .await?;

    let records_count = provider_records.len();
    for provider_record in provider_records {
        sqlx::query(
            r#"INSERT INTO dns_records (zone_id, name, "type", value, ttl, priority) VALUES ($1, $2, $3, $4, $5, $6)"#
        )
        .bind(zone_id)
        .bind(&provider_record.name)
        .bind(&provider_record.record_type)
        .bind(&provider_record.content)
        .bind(provider_record.ttl as i32)
        .bind(provider_record.priority.unwrap_or(0) as i32)
        .execute(&state.db)
        .await?;
    }

    Ok(Json(serde_json::json!({
        "message": "DNS zone synchronized successfully",
        "records_synced": records_count
    })))
}

pub async fn zone_transfer(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let user_id = claims_user_id(&claims)?;
    let zone = ensure_zone_owner(&state, zone_id, user_id).await?;

    // Get DNS provider
    let provider = state.dns_providers.get(&zone.dns_provider)
        .ok_or_else(|| ApiError::BadRequest(format!("DNS provider '{}' not available", zone.dns_provider)))?;

    // Export zone from provider
    let provider_zone_id = zone.provider_zone_id.clone().unwrap_or_default();
    let zone_file = provider.export_zone(&provider_zone_id).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    Ok(Json(serde_json::json!({
        "message": "Zone transfer completed",
        "zone_file": zone_file
    })))
}

pub async fn enable_dnssec(
    State(state): State<AppState>,
    claims: Claims,
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let user_id = claims_user_id(&claims)?;
    let zone = ensure_zone_owner(&state, zone_id, user_id).await?;

    // Get DNS provider
    let provider = state.dns_providers.get(&zone.dns_provider)
        .ok_or_else(|| ApiError::BadRequest(format!("DNS provider '{}' not available", zone.dns_provider)))?;

    // Enable DNSSEC
    let provider_zone_id = zone.provider_zone_id.clone().unwrap_or_default();
    provider.set_dnssec(&provider_zone_id, true).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    // Update database
    sqlx::query("UPDATE dns_zones SET dnssec_enabled = true WHERE id = $1")
        .bind(zone_id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "message": "DNSSEC enabled successfully",
        "zone_id": zone_id
    })))
}

/// Fetch a DNS zone by id, ensuring it belongs to the authenticated user.
/// Returns `NotFound` when the zone does not exist or is owned by someone else,
/// so callers never leak the existence of another user's zones.
async fn ensure_zone_owner(state: &AppState, zone_id: Uuid, user_id: Uuid) -> ApiResult<DnsZone> {
    sqlx::query_as::<_, DnsZone>("SELECT * FROM dns_zones WHERE id = $1 AND user_id = $2")
        .bind(zone_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}