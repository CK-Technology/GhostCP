use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;
use super::ApiResult;

pub async fn list_mail_domains(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"domains": [], "message": "Mail domains - TODO"})))
}

pub async fn create_mail_domain(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Create mail domain - TODO"})))
}

pub async fn list_mail_accounts(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"accounts": [], "message": "Mail accounts - TODO"})))
}

pub async fn create_mail_account(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::json!({"message": "Create mail account - TODO"})))
}