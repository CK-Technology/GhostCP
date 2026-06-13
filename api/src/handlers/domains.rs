use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    handlers::auth::Claims,
    models::{CreateWebDomainRequest, WebDomain},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListWebDomainsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListWebDomainsResponse {
    pub domains: Vec<WebDomain>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_web_domains(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListWebDomainsQuery>,
) -> ApiResult<Json<ListWebDomainsResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let domains = sqlx::query_as::<_, WebDomain>(
        "SELECT * FROM web_domains WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM web_domains WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListWebDomainsResponse {
        domains,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_web_domain(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateWebDomainRequest>,
) -> ApiResult<Json<WebDomain>> {
    let user_id = claims_user_id(&claims)?;

    if payload.domain.trim().is_empty() {
        return Err(ApiError::ValidationError("Domain is required".to_string()));
    }

    let domain = sqlx::query_as::<_, WebDomain>(
        r#"
        INSERT INTO web_domains (
            user_id, domain, ip_address, ipv6_address,
            web_template, backend_template, proxy_template, proxy_extensions,
            aliases, ssl_enabled, letsencrypt_enabled, letsencrypt_wildcard
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
        ) RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.domain)
    .bind(payload.ip_address)
    .bind(payload.ipv6_address)
    .bind(payload.web_template.as_deref().unwrap_or("default"))
    .bind(payload.backend_template.as_deref().unwrap_or("default"))
    .bind(payload.proxy_template.as_deref())
    .bind(payload.proxy_extensions.as_deref())
    .bind(payload.aliases.as_deref())
    .bind(payload.ssl_enabled.unwrap_or(false))
    .bind(payload.letsencrypt_enabled.unwrap_or(false))
    .bind(payload.letsencrypt_wildcard.unwrap_or(false))
    .fetch_one(&state.db)
    .await
    .map_err(map_unique_violation)?;

    Ok(Json(domain))
}

pub async fn get_web_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
) -> ApiResult<Json<WebDomain>> {
    let user_id = claims_user_id(&claims)?;

    let domain = sqlx::query_as::<_, WebDomain>(
        "SELECT * FROM web_domains WHERE id = $1 AND user_id = $2",
    )
    .bind(domain_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(domain))
}

#[derive(Debug, Deserialize)]
pub struct EnableSslRequest {
    pub letsencrypt: Option<bool>,
    pub force_https: Option<bool>,
    pub hsts: Option<bool>,
}

pub async fn enable_ssl(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
    Json(payload): Json<EnableSslRequest>,
) -> ApiResult<Json<WebDomain>> {
    let user_id = claims_user_id(&claims)?;

    let domain = sqlx::query_as::<_, WebDomain>(
        r#"
        UPDATE web_domains
        SET ssl_enabled = TRUE,
            letsencrypt_enabled = $3,
            ssl_force = $4,
            ssl_hsts = $5
        WHERE id = $1 AND user_id = $2
        RETURNING *
        "#,
    )
    .bind(domain_id)
    .bind(user_id)
    .bind(payload.letsencrypt.unwrap_or(true))
    .bind(payload.force_https.unwrap_or(true))
    .bind(payload.hsts.unwrap_or(false))
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(domain))
}

fn map_unique_violation(err: sqlx::Error) -> ApiError {
    if err.to_string().contains("duplicate key") {
        ApiError::ValidationError("Domain already exists for this user".to_string())
    } else {
        ApiError::Database(err)
    }
}
