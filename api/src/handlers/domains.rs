use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;
use super::ApiResult;

pub async fn list_web_domains(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"domains": [], "message": "Web domains endpoint - TODO"})))
}

pub async fn create_web_domain(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Create web domain - TODO"})))
}

pub async fn get_web_domain(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Get web domain - TODO"})))
}