use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use uuid::Uuid;
use crate::AppState;
use crate::models::users::{User, UserRole};
use crate::auth::totp::{TotpManager, TotpSecret};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDto {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user_id
    pub username: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
}

// JWT secret key - in production, load from environment
const JWT_SECRET: &[u8] = b"your-secret-key-change-in-production";

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Find user by username or email
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, email, password_hash, role as "role: UserRole", 
               status as "status: _", quota_mb, created_at, updated_at
        FROM users 
        WHERE username = $1 OR email = $1
        "#,
        payload.username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = user.ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let argon2 = Argon2::default();
    argon2.verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Check if 2FA is enabled and required
    let totp_data = sqlx::query!(
        "SELECT enabled, verified, secret FROM user_totp_secrets WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(totp) = totp_data {
        if totp.enabled && totp.verified {
            // 2FA is enabled - require TOTP code
            let totp_code = payload.totp_code.ok_or(StatusCode::UNAUTHORIZED)?;
            
            let totp_manager = TotpManager::new();
            let is_valid = totp_manager.verify_totp(&totp.secret, &totp_code, 1)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            if !is_valid {
                return Err(StatusCode::UNAUTHORIZED);
            }

            // Update last used timestamp
            sqlx::query!(
                "UPDATE user_totp_secrets SET last_used = NOW() WHERE user_id = $1",
                user.id
            )
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    // Generate JWT token
    let now = Utc::now();
    let expiry = now + Duration::hours(24);
    
    let claims = Claims {
        sub: user.id.to_string(),
        username: user.username.clone(),
        role: format!("{:?}", user.role),
        exp: expiry.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET)
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update last login
    sqlx::query!(
        "UPDATE users SET updated_at = NOW() WHERE id = $1",
        user.id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = LoginResponse {
        token,
        user: UserDto {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        },
    };

    Ok(Json(response))
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate input
    if payload.username.len() < 3 || payload.username.len() > 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    if !payload.email.contains('@') {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    if payload.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user already exists
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM users WHERE username = $1 OR email = $2",
        payload.username,
        payload.email
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if exists.count.unwrap_or(0) > 0 {
        return Err(StatusCode::CONFLICT);
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    // Create user
    let user_id = Uuid::new_v4();
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, username, email, password_hash, role, status, quota_mb)
        VALUES ($1, $2, $3, $4, 'user', 'active', 10240)
        RETURNING id, username, email, password_hash, role as "role: UserRole", 
                  status as "status: _", quota_mb, created_at, updated_at
        "#,
        user_id,
        payload.username,
        payload.email,
        password_hash
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate JWT token
    let now = Utc::now();
    let expiry = now + Duration::hours(24);
    
    let claims = Claims {
        sub: user.id.to_string(),
        username: user.username.clone(),
        role: format!("{:?}", user.role),
        exp: expiry.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET)
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = LoginResponse {
        token,
        user: UserDto {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        },
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn refresh_token(
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Decode and validate the existing token
    let token_data = decode::<Claims>(
        &payload.token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default()
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Generate a new token with extended expiry
    let now = Utc::now();
    let expiry = now + Duration::hours(24);
    
    let claims = Claims {
        sub: token_data.claims.sub,
        username: token_data.claims.username,
        role: token_data.claims.role,
        exp: expiry.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET)
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "token": token })))
}

pub async fn change_password(
    State(state): State<AppState>,
    claims: Claims,  // This would come from auth middleware
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get current user
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify current password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let argon2 = Argon2::default();
    argon2.verify_password(payload.current_password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = argon2
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    // Update password
    sqlx::query!(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        new_hash,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "message": "Password changed successfully" })))
}

pub async fn logout() -> impl IntoResponse {
    // Client-side will remove the token
    // We could implement token blacklisting here if needed
    Json(serde_json::json!({ "message": "Logged out successfully" }))
}

pub async fn me(
    State(state): State<AppState>,
    claims: Claims,  // This would come from auth middleware
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, email, password_hash, role as "role: UserRole", 
               status as "status: _", quota_mb, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let user_dto = UserDto {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
    };

    Ok(Json(user_dto))
}

// Middleware to extract and validate JWT claims
pub async fn auth_middleware(
    bearer_token: Option<String>,
) -> Result<Claims, StatusCode> {
    let token = bearer_token.ok_or(StatusCode::UNAUTHORIZED)?;
    let token = token.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default()
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(token_data.claims)
}