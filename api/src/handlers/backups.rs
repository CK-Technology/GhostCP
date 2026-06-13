use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    handlers::auth::Claims,
    models::{BackupConfig, CreateBackupConfigRequest},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

const VALID_BACKENDS: [&str; 6] = ["s3", "sftp", "local", "b2", "azure", "gcs"];

#[derive(Debug, Deserialize)]
pub struct ListBackupConfigsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListBackupConfigsResponse {
    pub configs: Vec<BackupConfig>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_backup_configs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListBackupConfigsQuery>,
) -> ApiResult<Json<ListBackupConfigsResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let configs = sqlx::query_as::<_, BackupConfig>(
        "SELECT * FROM backup_configs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_configs WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListBackupConfigsResponse {
        configs,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_backup_config(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateBackupConfigRequest>,
) -> ApiResult<Json<BackupConfig>> {
    let user_id = claims_user_id(&claims)?;

    if payload.name.trim().is_empty() {
        return Err(ApiError::ValidationError("Name is required".to_string()));
    }
    if !VALID_BACKENDS.contains(&payload.backend_type.as_str()) {
        return Err(ApiError::ValidationError(format!(
            "Unsupported backend type '{}'",
            payload.backend_type
        )));
    }
    if payload.repository_password.is_empty() {
        return Err(ApiError::ValidationError(
            "Repository password is required".to_string(),
        ));
    }

    let retention = payload
        .retention_policy
        .unwrap_or_else(|| json!({"daily": 7, "weekly": 4, "monthly": 6, "yearly": 2}));

    let config = sqlx::query_as::<_, BackupConfig>(
        r#"
        INSERT INTO backup_configs (
            user_id, name, include_files, include_databases, include_mail,
            included_paths, excluded_paths, included_databases,
            backend_type, backend_config, repository_password,
            schedule_cron, retention_policy
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.name)
    .bind(payload.include_files.unwrap_or(true))
    .bind(payload.include_databases.unwrap_or(true))
    .bind(payload.include_mail.unwrap_or(true))
    .bind(payload.included_paths.as_deref())
    .bind(payload.excluded_paths.as_deref())
    .bind(payload.included_databases.as_deref())
    .bind(&payload.backend_type)
    .bind(&payload.backend_config)
    .bind(&payload.repository_password)
    .bind(payload.schedule_cron.as_deref())
    .bind(&retention)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("A backup config with this name already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    Ok(Json(config))
}
