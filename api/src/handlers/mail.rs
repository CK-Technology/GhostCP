use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    handlers::auth::Claims,
    models::{CreateMailAccountRequest, CreateMailDomainRequest, MailAccount, MailDomain},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListMailDomainsResponse {
    pub domains: Vec<MailDomain>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_mail_domains(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<PaginationQuery>,
) -> ApiResult<Json<ListMailDomainsResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let domains = sqlx::query_as::<_, MailDomain>(
        "SELECT * FROM mail_domains WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mail_domains WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListMailDomainsResponse {
        domains,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_mail_domain(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateMailDomainRequest>,
) -> ApiResult<Json<MailDomain>> {
    let user_id = claims_user_id(&claims)?;

    if payload.domain.trim().is_empty() {
        return Err(ApiError::ValidationError("Domain is required".to_string()));
    }

    let domain = sqlx::query_as::<_, MailDomain>(
        r#"
        INSERT INTO mail_domains (
            user_id, domain, dkim_enabled, dkim_selector,
            antispam_enabled, antivirus_enabled,
            catchall_enabled, catchall_destination, rate_limit
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.domain)
    .bind(payload.dkim_enabled.unwrap_or(true))
    .bind(payload.dkim_selector.as_deref().unwrap_or("default"))
    .bind(payload.antispam_enabled.unwrap_or(true))
    .bind(payload.antivirus_enabled.unwrap_or(false))
    .bind(payload.catchall_enabled.unwrap_or(false))
    .bind(payload.catchall_destination.as_deref())
    .bind(payload.rate_limit.unwrap_or(100))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("Mail domain already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    Ok(Json(domain))
}

#[derive(Debug, Serialize)]
pub struct ListMailAccountsResponse {
    pub accounts: Vec<MailAccount>,
    pub total: u32,
}

pub async fn list_mail_accounts(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
) -> ApiResult<Json<ListMailAccountsResponse>> {
    let user_id = claims_user_id(&claims)?;
    ensure_domain_owner(&state, domain_id, user_id).await?;

    let accounts = sqlx::query_as::<_, MailAccount>(
        "SELECT * FROM mail_accounts WHERE domain_id = $1 ORDER BY username",
    )
    .bind(domain_id)
    .fetch_all(&state.db)
    .await?;

    let total = accounts.len() as u32;
    Ok(Json(ListMailAccountsResponse { accounts, total }))
}

pub async fn create_mail_account(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
    Json(payload): Json<CreateMailAccountRequest>,
) -> ApiResult<Json<MailAccount>> {
    let user_id = claims_user_id(&claims)?;
    let domain = ensure_domain_owner(&state, domain_id, user_id).await?;

    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return Err(ApiError::ValidationError(
            "Username and password are required".to_string(),
        ));
    }

    let password_hash = hash_password(&payload.password)?;
    let email = format!("{}@{}", payload.username, domain.domain);

    let account = sqlx::query_as::<_, MailAccount>(
        r#"
        INSERT INTO mail_accounts (
            domain_id, username, email, password_hash,
            quota_mb, forward_to, forward_only
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(domain_id)
    .bind(&payload.username)
    .bind(&email)
    .bind(&password_hash)
    .bind(payload.quota_mb.unwrap_or(0))
    .bind(payload.forward_to.as_deref())
    .bind(payload.forward_only.unwrap_or(false))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("Mail account already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    Ok(Json(account))
}

/// Verify the mail domain exists and belongs to the authenticated user.
async fn ensure_domain_owner(
    state: &AppState,
    domain_id: Uuid,
    user_id: Uuid,
) -> ApiResult<MailDomain> {
    sqlx::query_as::<_, MailDomain>(
        "SELECT * FROM mail_domains WHERE id = $1 AND user_id = $2",
    )
    .bind(domain_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)
}

fn hash_password(password: &str) -> ApiResult<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::InternalError(format!("Password hashing failed: {}", e)))
}
