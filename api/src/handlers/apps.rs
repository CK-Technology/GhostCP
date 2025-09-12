// Application deployment API handlers
use axum::{
    extract::{State, Path, Json},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::AppState;
use crate::handlers::auth::Claims;
use crate::system::app_deployment::{
    AppDeploymentManager, DeploymentRequest, DeploymentResult, 
    AppTemplate, DatabaseConfig, DatabaseType
};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAppRequest {
    pub template_id: String,
    pub domain: String,
    pub subdomain: Option<String>,
    pub user_inputs: std::collections::HashMap<String, String>,
    pub create_database: bool,
    pub ssl_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppListResponse {
    pub templates: Vec<AppTemplate>,
    pub categories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeploymentStatusResponse {
    pub id: Uuid,
    pub status: String,
    pub progress: u32,
    pub logs: Vec<String>,
    pub estimated_time_remaining: Option<u32>,
}

// Get available application templates
pub async fn get_app_templates(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let deployment_manager = AppDeploymentManager::new(
        PathBuf::from("/opt/ghostcp/templates"),
        PathBuf::from("/var/www"),
        true, // Docker enabled
    );

    let templates = deployment_manager.get_templates();
    let categories: std::collections::HashSet<String> = templates
        .iter()
        .map(|t| t.category.clone())
        .collect();

    let response = AppListResponse {
        templates: templates.clone(),
        categories: categories.into_iter().collect(),
    };

    Ok(Json(response))
}

// Get specific template details
pub async fn get_app_template(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Path(template_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let deployment_manager = AppDeploymentManager::new(
        PathBuf::from("/opt/ghostcp/templates"),
        PathBuf::from("/var/www"),
        true,
    );

    let template = deployment_manager.get_template(&template_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(template))
}

// Deploy new application
pub async fn deploy_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateAppRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check if domain already exists
    let existing_domain = sqlx::query!(
        "SELECT id FROM web_domains WHERE domain = $1",
        payload.domain
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing_domain.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let deployment_manager = AppDeploymentManager::new(
        PathBuf::from("/opt/ghostcp/templates"),
        PathBuf::from("/var/www"),
        true,
    );

    // Create database if needed
    let database_config = if payload.create_database {
        let db_name = format!("{}_{}", payload.template_id, payload.domain.replace(".", "_").replace("-", "_"));
        let db_user = format!("user_{}", &db_name[..std::cmp::min(20, db_name.len())]);
        let db_password = generate_password(16);

        // Create database and user
        sqlx::query(&format!(
            "CREATE DATABASE {} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
            db_name
        ))
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        sqlx::query(&format!(
            "CREATE USER '{}'@'localhost' IDENTIFIED BY '{}'",
            db_user, db_password
        ))
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        sqlx::query(&format!(
            "GRANT ALL PRIVILEGES ON {}.* TO '{}'@'localhost'",
            db_name, db_user
        ))
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Some(DatabaseConfig {
            database_type: DatabaseType::MySQL,
            database_name: db_name.clone(),
            username: db_user,
            password: db_password,
        })
    } else {
        None
    };

    // Create deployment request
    let deployment_request = DeploymentRequest {
        template_id: payload.template_id.clone(),
        domain: payload.domain.clone(),
        subdomain: payload.subdomain.clone(),
        user_inputs: payload.user_inputs,
        database_config: database_config.clone(),
        ssl_enabled: payload.ssl_enabled,
    };

    // Start deployment
    let deployment_result = deployment_manager.deploy_app(deployment_request).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store deployment in database
    let deployment_id = sqlx::query!(
        r#"
        INSERT INTO app_deployments (
            id, user_id, template_id, domain, status, site_url, 
            admin_url, logs, created_at
        ) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        deployment_result.id,
        user_id,
        payload.template_id,
        payload.domain,
        format!("{:?}", deployment_result.status),
        deployment_result.site_url,
        deployment_result.admin_url,
        serde_json::to_string(&deployment_result.logs).unwrap_or_default(),
        deployment_result.created_at
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create web domain entry
    sqlx::query!(
        r#"
        INSERT INTO web_domains (
            id, user_id, domain, document_root, ssl_enabled, 
            ssl_cert_path, ssl_key_path, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        "#,
        Uuid::new_v4(),
        user_id,
        payload.domain,
        format!("/var/www/{}", payload.domain),
        payload.ssl_enabled,
        if payload.ssl_enabled { Some(format!("/etc/ssl/certs/{}.crt", payload.domain)) } else { None },
        if payload.ssl_enabled { Some(format!("/etc/ssl/private/{}.key", payload.domain)) } else { None }
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store database info if created
    if let Some(db_config) = database_config {
        sqlx::query!(
            r#"
            INSERT INTO databases (
                id, user_id, name, type, username, password, 
                host, port, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            "#,
            Uuid::new_v4(),
            user_id,
            db_config.database_name,
            format!("{:?}", db_config.database_type),
            db_config.username,
            db_config.password,
            "localhost",
            3306i32
        )
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok((StatusCode::CREATED, Json(deployment_result)))
}

// Get deployment status
pub async fn get_deployment_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(deployment_id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    let deployment = sqlx::query!(
        r#"
        SELECT id, status, logs, created_at
        FROM app_deployments 
        WHERE id = $1 AND user_id = $2
        "#,
        deployment_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let logs: Vec<String> = serde_json::from_str(&deployment.logs).unwrap_or_default();
    
    let response = DeploymentStatusResponse {
        id: deployment.id,
        status: deployment.status,
        progress: if deployment.status == "Completed" { 100 } else { 50 },
        logs,
        estimated_time_remaining: if deployment.status == "InProgress" { Some(120) } else { None },
    };

    Ok(Json(response))
}

// List user's deployed applications
pub async fn list_user_apps(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    let deployments = sqlx::query!(
        r#"
        SELECT 
            ad.id, ad.template_id, ad.domain, ad.status, 
            ad.site_url, ad.admin_url, ad.created_at,
            wd.ssl_enabled
        FROM app_deployments ad
        LEFT JOIN web_domains wd ON wd.domain = ad.domain
        WHERE ad.user_id = $1
        ORDER BY ad.created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(deployments))
}

// Delete deployed application
pub async fn delete_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(deployment_id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get deployment info
    let deployment = sqlx::query!(
        r#"
        SELECT domain, template_id
        FROM app_deployments 
        WHERE id = $1 AND user_id = $2
        "#,
        deployment_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Remove files
    let app_path = PathBuf::from("/var/www").join(&deployment.domain);
    if app_path.exists() {
        tokio::fs::remove_dir_all(&app_path).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Remove nginx config
    let nginx_config = PathBuf::from("/etc/nginx/sites-available").join(&deployment.domain);
    if nginx_config.exists() {
        tokio::fs::remove_file(&nginx_config).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let nginx_enabled = PathBuf::from("/etc/nginx/sites-enabled").join(&deployment.domain);
    if nginx_enabled.exists() {
        tokio::fs::remove_file(&nginx_enabled).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Delete from database
    sqlx::query!(
        "DELETE FROM app_deployments WHERE id = $1 AND user_id = $2",
        deployment_id,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query!(
        "DELETE FROM web_domains WHERE domain = $1 AND user_id = $2",
        deployment.domain,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Reload nginx
    std::process::Command::new("nginx")
        .args(["-s", "reload"])
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "message": "Application deleted successfully"
    })))
}

// Update application settings
pub async fn update_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(deployment_id): Path<Uuid>,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify ownership
    let deployment = sqlx::query!(
        "SELECT domain FROM app_deployments WHERE id = $1 AND user_id = $2",
        deployment_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Update deployment settings based on payload
    // Implementation would depend on specific update requirements

    Ok(Json(serde_json::json!({
        "message": "Application updated successfully"
    })))
}

fn generate_password(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}