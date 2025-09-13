// 2FA/TOTP authentication handlers
use axum::{
    extract::{State, Json, Extension},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use crate::AppState;
use crate::handlers::auth::Claims;
use crate::auth::totp::{TotpManager, TotpSetupData};
use crate::models::user::User;

#[derive(Debug, Serialize, Deserialize)]
pub struct EnableTotpRequest {
    pub password: String, // Require password confirmation
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyTotpRequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisableTotpRequest {
    pub password: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpStatusResponse {
    pub enabled: bool,
    pub verified: bool,
    pub backup_codes_remaining: u32,
}

// Start TOTP setup process
pub async fn setup_totp(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EnableTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify user's password first
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify password
    let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let argon2 = argon2::Argon2::default();
    argon2.verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Generate TOTP secret
    let totp_manager = TotpManager::new();
    let setup_data = totp_manager.generate_secret(user_id, &claims.username, "GhostCP")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store the secret in database (not yet verified)
    let backup_codes_json = serde_json::to_string(&setup_data.backup_codes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query!(
        r#"
        INSERT INTO user_totp_secrets (user_id, secret, backup_codes, enabled, verified, created_at)
        VALUES ($1, $2, $3, false, false, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            secret = $2,
            backup_codes = $3,
            enabled = false,
            verified = false,
            created_at = NOW()
        "#,
        user_id,
        setup_data.secret,
        backup_codes_json
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "qr_code": setup_data.qr_code_svg,
        "manual_entry_key": setup_data.manual_entry_key,
        "backup_codes": setup_data.backup_codes
    })))
}

// Verify and enable TOTP
pub async fn verify_totp(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<VerifyTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get the pending TOTP secret
    let totp_data = sqlx::query!(
        "SELECT secret FROM user_totp_secrets WHERE user_id = $1 AND verified = false",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify the TOTP code
    let totp_manager = TotpManager::new();
    let is_valid = totp_manager.verify_totp(&totp_data.secret, &payload.totp_code, 1)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Enable and verify TOTP
    sqlx::query!(
        "UPDATE user_totp_secrets SET enabled = true, verified = true WHERE user_id = $1",
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "message": "2FA enabled successfully",
        "enabled": true
    })))
}

// Disable TOTP
pub async fn disable_totp(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<DisableTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify user's password
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify password
    let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let argon2 = argon2::Argon2::default();
    argon2.verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Get current TOTP data
    let totp_data = sqlx::query!(
        "SELECT secret, backup_codes FROM user_totp_secrets WHERE user_id = $1 AND enabled = true",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify TOTP or backup code
    let mut is_valid = false;
    
    if let Some(totp_code) = payload.totp_code {
        let totp_manager = TotpManager::new();
        is_valid = totp_manager.verify_totp(&totp_data.secret, &totp_code, 1)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else if let Some(backup_code) = payload.backup_code {
        let mut backup_codes: Vec<String> = serde_json::from_str(&totp_data.backup_codes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        let totp_manager = TotpManager::new();
        is_valid = totp_manager.verify_backup_code(&mut backup_codes, &backup_code);
        
        if is_valid {
            // Update backup codes in database
            let updated_codes = serde_json::to_string(&backup_codes)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            sqlx::query!(
                "UPDATE user_totp_secrets SET backup_codes = $1 WHERE user_id = $2",
                updated_codes,
                user_id
            )
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Disable TOTP
    sqlx::query!(
        "DELETE FROM user_totp_secrets WHERE user_id = $1",
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "message": "2FA disabled successfully",
        "enabled": false
    })))
}

// Get TOTP status
pub async fn get_totp_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    let totp_data = sqlx::query!(
        "SELECT enabled, verified, backup_codes FROM user_totp_secrets WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (enabled, verified, backup_codes_remaining) = if let Some(data) = totp_data {
        let backup_codes: Vec<String> = serde_json::from_str(&data.backup_codes)
            .unwrap_or_default();
        
        (data.enabled, data.verified, backup_codes.len() as u32)
    } else {
        (false, false, 0)
    };

    Ok(Json(TotpStatusResponse {
        enabled,
        verified,
        backup_codes_remaining,
    }))
}

// Generate new backup codes
pub async fn generate_backup_codes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<VerifyTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get current TOTP data
    let totp_data = sqlx::query!(
        "SELECT secret FROM user_totp_secrets WHERE user_id = $1 AND enabled = true",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Verify TOTP code
    let totp_manager = TotpManager::new();
    let is_valid = totp_manager.verify_totp(&totp_data.secret, &payload.totp_code, 1)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Generate new backup codes
    let new_backup_codes = totp_manager.generate_backup_codes();
    let backup_codes_json = serde_json::to_string(&new_backup_codes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update database
    sqlx::query!(
        "UPDATE user_totp_secrets SET backup_codes = $1 WHERE user_id = $2",
        backup_codes_json,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "backup_codes": new_backup_codes,
        "message": "New backup codes generated successfully"
    })))
}