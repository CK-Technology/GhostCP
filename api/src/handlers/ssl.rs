use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    handlers::auth::Claims,
    models::{RequestCertificateRequest, SslCertificate},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListCertificatesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<SslCertificate>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_certificates(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListCertificatesQuery>,
) -> ApiResult<Json<ListCertificatesResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let certificates = sqlx::query_as::<_, SslCertificate>(
        "SELECT * FROM ssl_certificates WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ssl_certificates WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListCertificatesResponse {
        certificates,
        total: total as u32,
        page,
        limit,
    }))
}

/// Provision a certificate.
///
/// Manual upload stores the supplied PEM material and marks the certificate
/// active. ACME requests (no PEM provided) are persisted inactive with the
/// requested provider/challenge so the issuance job runner can complete them.
pub async fn request_certificate(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<RequestCertificateRequest>,
) -> ApiResult<Json<SslCertificate>> {
    let user_id = claims_user_id(&claims)?;

    if payload.domain.trim().is_empty() {
        return Err(ApiError::ValidationError("Domain is required".to_string()));
    }

    let manual_upload = payload.certificate_pem.is_some() && payload.private_key_pem.is_some();
    if payload.certificate_pem.is_some() != payload.private_key_pem.is_some() {
        return Err(ApiError::ValidationError(
            "Both certificate_pem and private_key_pem must be provided for manual upload"
                .to_string(),
        ));
    }

    let acme_provider = if manual_upload {
        None
    } else {
        Some(payload.acme_provider.as_deref().unwrap_or("letsencrypt").to_string())
    };
    let acme_challenge_type = if manual_upload {
        None
    } else {
        Some(payload.acme_challenge_type.as_deref().unwrap_or("http01").to_string())
    };

    let certificate = sqlx::query_as::<_, SslCertificate>(
        r#"
        INSERT INTO ssl_certificates (
            user_id, domain, certificate_pem, private_key_pem, certificate_chain_pem,
            san_domains, acme_provider, acme_challenge_type,
            auto_renew, is_active, is_wildcard
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.domain)
    .bind(payload.certificate_pem.as_deref().unwrap_or(""))
    .bind(payload.private_key_pem.as_deref().unwrap_or(""))
    .bind(payload.certificate_chain_pem.as_deref())
    .bind(payload.san_domains.as_deref())
    .bind(acme_provider)
    .bind(acme_challenge_type)
    .bind(payload.auto_renew.unwrap_or(true))
    .bind(manual_upload) // active immediately only for manual uploads
    .bind(payload.is_wildcard.unwrap_or(false))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("A certificate for this domain already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    Ok(Json(certificate))
}

/// Mark a certificate for renewal. Flags it for the ACME job runner by clearing
/// the active state and bumping `updated_at`; the runner performs the issuance.
pub async fn renew_certificate(
    State(state): State<AppState>,
    claims: Claims,
    Path(cert_id): Path<Uuid>,
) -> ApiResult<Json<SslCertificate>> {
    let user_id = claims_user_id(&claims)?;

    let certificate = sqlx::query_as::<_, SslCertificate>(
        r#"
        UPDATE ssl_certificates
        SET updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND user_id = $2
        RETURNING *
        "#,
    )
    .bind(cert_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(certificate))
}
