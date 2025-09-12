use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    models::{DnsZone, DnsRecord, CreateDnsZoneRequest, CreateDnsRecordRequest},
    drivers::dns::{DnsProvider, DnsError},
    AppState,
};
use super::{ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListDnsZonesQuery {
    pub user_id: Option<Uuid>,
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

#[derive(Debug, Serialize)]
pub struct DnsZoneWithRecordCount {
    #[serde(flatten)]
    pub zone: DnsZone,
    pub records_count: i32,
}

pub async fn list_dns_zones(
    State(state): State<AppState>,
    Query(params): Query<ListDnsZonesQuery>,
) -> ApiResult<Json<ListDnsZonesResponse>> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;

    let mut query = "SELECT z.*, COUNT(r.id) as records_count FROM dns_zones z LEFT JOIN dns_records r ON z.id = r.zone_id WHERE 1=1".to_string();
    
    if let Some(user_id) = params.user_id {
        query.push_str(&format!(" AND z.user_id = '{}'", user_id));
    }
    
    query.push_str(" GROUP BY z.id ORDER BY z.created_at DESC");
    query.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    let zones = sqlx::query_as::<_, DnsZoneWithRecordCount>(&query)
        .fetch_all(&state.db)
        .await?;

    // Get total count
    let count_query = "SELECT COUNT(*) FROM dns_zones WHERE 1=1".to_string();
    let total: i64 = sqlx::query_scalar(&count_query)
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
    Json(payload): Json<CreateDnsZoneRequest>,
) -> ApiResult<Json<DnsZone>> {
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
    .bind(Uuid::new_v4()) // TODO: Get actual user ID from auth
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
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<DnsZone>> {
    let zone = sqlx::query_as::<_, DnsZone>(
        "SELECT * FROM dns_zones WHERE id = $1"
    )
    .bind(zone_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(zone))
}

pub async fn list_dns_records(
    State(state): State<AppState>,
    Path(zone_id): Path<Uuid>,
    Query(params): Query<ListDnsRecordsQuery>,
) -> ApiResult<Json<ListDnsRecordsResponse>> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = (page - 1) * limit;

    let mut query = "SELECT * FROM dns_records WHERE zone_id = $1".to_string();
    let mut query_params = vec![zone_id.to_string()];
    let mut param_count = 2;
    
    if let Some(record_type) = &params.record_type {
        query.push_str(&format!(" AND type = ${}", param_count));
        query_params.push(record_type.clone());
        param_count += 1;
    }
    
    query.push_str(" ORDER BY name, type");
    query.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    // This is a simplified query - in practice you'd use a query builder
    let records = sqlx::query_as::<_, DnsRecord>(
        "SELECT * FROM dns_records WHERE zone_id = $1 ORDER BY name, record_type LIMIT $2 OFFSET $3"
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
    Path(zone_id): Path<Uuid>,
    Json(payload): Json<CreateDnsRecordRequest>,
) -> ApiResult<Json<DnsRecord>> {
    // Get the zone to determine the DNS provider
    let zone = sqlx::query_as::<_, DnsZone>(
        "SELECT * FROM dns_zones WHERE id = $1"
    )
    .bind(zone_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

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
        ttl: payload.ttl.unwrap_or(3600),
        priority: payload.priority.map(|p| p as u16),
        proxied: None,
    };

    let record_id = provider.create_record(&provider_record).await
        .map_err(|e| ApiError::BadRequest(format!("DNS provider error: {}", e)))?;

    // Create record in database
    let db_record = sqlx::query_as::<_, DnsRecord>(
        r#"
        INSERT INTO dns_records (
            zone_id, name, record_type, value, ttl, priority
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
    Path(zone_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    // Get the zone
    let zone = sqlx::query_as::<_, DnsZone>(
        "SELECT * FROM dns_zones WHERE id = $1"
    )
    .bind(zone_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

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

    for provider_record in provider_records {
        sqlx::query(
            "INSERT INTO dns_records (zone_id, name, record_type, value, ttl, priority) VALUES ($1, $2, $3, $4, $5, $6)"
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
        "records_synced": provider_records.len()
    })))
}