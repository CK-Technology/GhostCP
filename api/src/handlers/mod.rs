pub mod auth;
pub mod users;
pub mod domains;
pub mod dns;
pub mod mail;
pub mod databases;
pub mod cron;
pub mod ssl;
pub mod backups;
pub mod jobs;
pub mod two_factor;
pub mod monitoring;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    NotFound,
    BadRequest(String),
    Unauthorized,
    Forbidden,
    InternalError(String),
    Database(sqlx::Error),
    ValidationError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::Database(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            ),
            ApiError::ValidationError(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::Database(err)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Resolve the authenticated user's UUID from validated JWT claims.
///
/// The auth middleware decodes the bearer token and inserts `Claims` into the
/// request extensions; `Claims` implements `FromRequestParts`, so protected
/// handlers can take it directly and call this to scope queries to the owner.
pub fn claims_user_id(claims: &auth::Claims) -> ApiResult<uuid::Uuid> {
    uuid::Uuid::parse_str(&claims.sub).map_err(|_| ApiError::Unauthorized)
}