use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    handlers::auth::Claims,
    models::{CreateSystemJobRequest, SystemJob},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListSystemJobsQuery {
    pub status: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListSystemJobsResponse {
    pub jobs: Vec<SystemJob>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_system_jobs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListSystemJobsQuery>,
) -> ApiResult<Json<ListSystemJobsResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let jobs = sqlx::query_as::<_, SystemJob>(
        r#"
        SELECT * FROM system_jobs
        WHERE user_id = $1 AND ($2::text IS NULL OR status = $2)
        ORDER BY scheduled_for DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(user_id)
    .bind(params.status.as_deref())
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_jobs WHERE user_id = $1 AND ($2::text IS NULL OR status = $2)",
    )
    .bind(user_id)
    .bind(params.status.as_deref())
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ListSystemJobsResponse {
        jobs,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_system_job(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateSystemJobRequest>,
) -> ApiResult<Json<SystemJob>> {
    let user_id = claims_user_id(&claims)?;

    if payload.job_type.trim().is_empty() {
        return Err(ApiError::ValidationError("Job type is required".to_string()));
    }

    let parameters = payload.parameters.unwrap_or_else(|| json!({}));

    let job = sqlx::query_as::<_, SystemJob>(
        r#"
        INSERT INTO system_jobs (
            job_type, user_id, parameters, priority, max_retries, scheduled_for
        ) VALUES (
            $1, $2, $3, $4, $5, COALESCE($6, CURRENT_TIMESTAMP)
        )
        RETURNING *
        "#,
    )
    .bind(&payload.job_type)
    .bind(user_id)
    .bind(&parameters)
    .bind(payload.priority.unwrap_or(0))
    .bind(payload.max_retries.unwrap_or(3))
    .bind(payload.scheduled_for)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(job))
}
