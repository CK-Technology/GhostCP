use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;
use super::ApiResult;

pub async fn list_certificates(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"certificates": [], "message": "SSL certificates - TODO"})))
}

pub async fn request_certificate(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Request certificate - TODO"})))
}
