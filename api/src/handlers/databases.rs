use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;
use super::ApiResult;

pub async fn list_databases(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"databases": [], "message": "Databases - TODO"})))
}

pub async fn create_database(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Create database - TODO"})))
}