use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::Claims,
    models::{CreateCronJobRequest, CronJob},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListCronJobsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListCronJobsResponse {
    pub jobs: Vec<CronJob>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_cron_jobs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListCronJobsQuery>,
) -> ApiResult<Json<ListCronJobsResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let jobs = sqlx::query_as::<_, CronJob>(
        "SELECT * FROM cron_jobs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cron_jobs WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListCronJobsResponse {
        jobs,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_cron_job(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateCronJobRequest>,
) -> ApiResult<Json<CronJob>> {
    let user_id = claims_user_id(&claims)?;

    if payload.command.trim().is_empty() {
        return Err(ApiError::ValidationError("Command is required".to_string()));
    }

    let job = sqlx::query_as::<_, CronJob>(
        r#"
        INSERT INTO cron_jobs (
            user_id, minute, hour, day, month, weekday,
            command, working_directory, log_output, email_output
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(payload.minute.as_deref().unwrap_or("*"))
    .bind(payload.hour.as_deref().unwrap_or("*"))
    .bind(payload.day.as_deref().unwrap_or("*"))
    .bind(payload.month.as_deref().unwrap_or("*"))
    .bind(payload.weekday.as_deref().unwrap_or("*"))
    .bind(&payload.command)
    .bind(payload.working_directory.as_deref())
    .bind(payload.log_output.unwrap_or(true))
    .bind(payload.email_output.unwrap_or(false))
    .fetch_one(&state.db)
    .await?;

    Ok(Json(job))
}
