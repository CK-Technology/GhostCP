use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;
use super::ApiResult;

pub async fn list_cron_jobs(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"jobs": [], "message": "Cron jobs - TODO"})))
}

pub async fn create_cron_job(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Create cron job - TODO"})))
}
