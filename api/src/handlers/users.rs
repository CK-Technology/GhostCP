use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    models::{CreateUserRequest, UpdateUserRequest, User, UserRole},
    AppState,
};
use super::{ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub role: Option<UserRole>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<User>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
    pub pages: u32,
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(params): Query<ListUsersQuery>,
) -> ApiResult<Json<ListUsersResponse>> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100); // Max 100 per page
    let offset = (page - 1) * limit;

    // Build query with filters
    let mut query = "SELECT * FROM users WHERE 1=1".to_string();
    let mut count_query = "SELECT COUNT(*) FROM users WHERE 1=1".to_string();
    
    if let Some(role) = &params.role {
        let role_filter = format!(" AND role = '{}'", role);
        query.push_str(&role_filter);
        count_query.push_str(&role_filter);
    }
    
    if let Some(search) = &params.search {
        let search_filter = format!(
            " AND (username ILIKE '%{}%' OR email ILIKE '%{}%' OR full_name ILIKE '%{}%')",
            search, search, search
        );
        query.push_str(&search_filter);
        count_query.push_str(&search_filter);
    }
    
    query.push_str(&format!(" ORDER BY created_at DESC LIMIT {} OFFSET {}", limit, offset));

    // Get total count
    let total_row = sqlx::query(&count_query)
        .fetch_one(&state.db)
        .await?;
    let total: i64 = total_row.get(0);
    
    // Get users
    let users = sqlx::query_as::<_, User>(&query)
        .fetch_all(&state.db)
        .await?;

    let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;

    Ok(Json(ListUsersResponse {
        users,
        total: total as u32,
        page,
        limit,
        pages: total_pages,
    }))
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> ApiResult<Json<User>> {
    // Validate input
    if payload.username.is_empty() || payload.email.is_empty() || payload.password.is_empty() {
        return Err(ApiError::ValidationError("Username, email, and password are required".to_string()));
    }

    // Hash password
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };
    
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| ApiError::InternalError(format!("Password hashing failed: {}", e)))?
        .to_string();

    // Set defaults from package or use system defaults
    let package_name = payload.package_name.unwrap_or_else(|| "default".to_string());
    let role = payload.role.unwrap_or(UserRole::User);
    
    // Create user
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (
            username, email, password_hash, full_name, package_name, role,
            disk_quota, bandwidth_quota, web_domains_limit, dns_domains_limit,
            mail_domains_limit, databases_limit, cron_jobs_limit,
            shell, language, timezone, home_dir
        ) VALUES (
            $1, $2, $3, $4, $5, $6::text::user_role,
            $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        )
        RETURNING *
        "#,
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&payload.full_name)
    .bind(&package_name)
    .bind(&role.to_string())
    .bind(payload.disk_quota.unwrap_or(0))
    .bind(payload.bandwidth_quota.unwrap_or(0))
    .bind(payload.web_domains_limit.unwrap_or(0))
    .bind(payload.dns_domains_limit.unwrap_or(0))
    .bind(payload.mail_domains_limit.unwrap_or(0))
    .bind(payload.databases_limit.unwrap_or(0))
    .bind(payload.cron_jobs_limit.unwrap_or(0))
    .bind(payload.shell.unwrap_or_else(|| "/bin/bash".to_string()))
    .bind(payload.language.unwrap_or_else(|| "en".to_string()))
    .bind(payload.timezone.unwrap_or_else(|| "UTC".to_string()))
    .bind(format!("/home/{}", payload.username))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            ApiError::ValidationError("Username or email already exists".to_string())
        } else {
            ApiError::Database(e)
        }
    })?;

    // TODO: Create system user, directories, etc.
    // This would call out to system scripts similar to HestiaCP's v-add-user

    Ok(Json(user))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(user))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> ApiResult<Json<User>> {
    // TODO: Implement proper dynamic update query
    // For now, just fetch and return existing user
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(user))
}