use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::Claims,
    models::{CreateDatabaseRequest, Database},
    AppState,
};
use super::{claims_user_id, ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListDatabasesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListDatabasesResponse {
    pub databases: Vec<Database>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_databases(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListDatabasesQuery>,
) -> ApiResult<Json<ListDatabasesResponse>> {
    let user_id = claims_user_id(&claims)?;
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    let databases = sqlx::query_as::<_, Database>(
        "SELECT * FROM databases WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListDatabasesResponse {
        databases,
        total: total as u32,
        page,
        limit,
    }))
}

pub async fn create_database(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateDatabaseRequest>,
) -> ApiResult<Json<Database>> {
    let user_id = claims_user_id(&claims)?;

    if payload.name.trim().is_empty() {
        return Err(ApiError::ValidationError("Database name is required".to_string()));
    }

    let db_type = payload.db_type.as_deref().unwrap_or("postgresql");
    if !matches!(db_type, "postgresql" | "mysql" | "mariadb") {
        return Err(ApiError::ValidationError(format!(
            "Unsupported database type '{}'",
            db_type
        )));
    }

    let port = payload.port.unwrap_or_else(|| Database::default_port(db_type));

    let database = sqlx::query_as::<_, Database>(
        r#"
        INSERT INTO databases (user_id, name, "type", host, port, charset)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(&payload.name)
    .bind(db_type)
    .bind(payload.host.as_deref().unwrap_or("localhost"))
    .bind(port)
    .bind(payload.charset.as_deref().unwrap_or("utf8mb4"))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("A database with this name and type already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    Ok(Json(database))
}
