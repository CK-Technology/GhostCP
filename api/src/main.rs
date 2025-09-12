use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod database;
mod models;
mod handlers;
mod auth;
mod templates;
mod jobs;
mod drivers;
mod system;
mod middleware;

use config::Config;
use drivers::dns::{DnsProvider, cloudflare::CloudflareDns, powerdns::PowerDns, local::LocalDns};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub dns_providers: Arc<HashMap<String, Arc<dyn DnsProvider>>>,
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "ghostcp-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        // API v1 routes
        .nest("/api/v1", api_v1_routes())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn api_v1_routes() -> Router<AppState> {
    use axum::middleware as axum_middleware;
    
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/refresh", post(handlers::auth::refresh_token))
        // Prometheus metrics endpoint (public for monitoring tools)
        .route("/metrics", get(handlers::monitoring::prometheus_metrics));
    
    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/auth/logout", post(handlers::auth::logout))
        .route("/auth/me", get(handlers::auth::me))
        .route("/auth/password", post(handlers::auth::change_password))
        .route("/users", get(handlers::users::list_users).post(handlers::users::create_user))
        .route("/users/:id", get(handlers::users::get_user).put(handlers::users::update_user))
        .route("/domains", get(handlers::domains::list_web_domains).post(handlers::domains::create_web_domain))
        .route("/domains/:id", get(handlers::domains::get_web_domain))
        .route("/domains/:id/ssl", post(handlers::domains::enable_ssl))
        .route("/dns", get(handlers::dns::list_dns_zones).post(handlers::dns::create_dns_zone))
        .route("/dns/:id", get(handlers::dns::get_dns_zone))
        .route("/dns/:id/records", get(handlers::dns::list_dns_records).post(handlers::dns::create_dns_record))
        .route("/dns/:id/sync", post(handlers::dns::sync_dns_zone))
        .route("/dns/:id/axfr", post(handlers::dns::zone_transfer))
        .route("/dns/:id/dnssec", post(handlers::dns::enable_dnssec))
        .route("/mail", get(handlers::mail::list_mail_domains).post(handlers::mail::create_mail_domain))
        .route("/mail/:id/accounts", get(handlers::mail::list_mail_accounts).post(handlers::mail::create_mail_account))
        .route("/databases", get(handlers::databases::list_databases).post(handlers::databases::create_database))
        .route("/cron", get(handlers::cron::list_cron_jobs).post(handlers::cron::create_cron_job))
        .route("/ssl", get(handlers::ssl::list_certificates).post(handlers::ssl::request_certificate))
        .route("/ssl/:id/renew", post(handlers::ssl::renew_certificate))
        .route("/backups", get(handlers::backups::list_backup_configs).post(handlers::backups::create_backup_config))
        .route("/jobs", get(handlers::jobs::list_system_jobs).post(handlers::jobs::create_system_job))
        // 2FA/TOTP routes
        .route("/auth/totp/setup", post(handlers::two_factor::setup_totp))
        .route("/auth/totp/verify", post(handlers::two_factor::verify_totp))
        .route("/auth/totp/disable", post(handlers::two_factor::disable_totp))
        .route("/auth/totp/status", get(handlers::two_factor::get_totp_status))
        .route("/auth/totp/backup-codes", post(handlers::two_factor::generate_backup_codes))
        // Monitoring routes
        .route("/monitoring/metrics", get(handlers::monitoring::get_current_metrics))
        .route("/monitoring/history", get(handlers::monitoring::get_metrics_history))
        .route("/monitoring/services", get(handlers::monitoring::get_service_status))
        .route("/monitoring/processes", get(handlers::monitoring::get_processes))
        .route("/monitoring/disk", get(handlers::monitoring::get_disk_usage))
        .route("/monitoring/network", get(handlers::monitoring::get_network_stats))
        .route("/monitoring/start", post(handlers::monitoring::start_metrics_collection))
        .layer(axum_middleware::from_fn(middleware::auth_middleware));
    
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ghostcp_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    
    // Connect to database
    let db = database::connect(&config.database_url).await?;
    
    // Run migrations
    database::migrate(&db).await?;
    
    // Initialize DNS providers
    let dns_providers = initialize_dns_providers(&config).await?;
    
    // Create app state
    let state = AppState { 
        db, 
        config: config.clone(),
        dns_providers: Arc::new(dns_providers),
    };
    
    // Create router
    let app = create_router(state).await;
    
    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("GhostCP API server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn initialize_dns_providers(config: &Config) -> Result<HashMap<String, Arc<dyn DnsProvider>>> {
    let mut providers: HashMap<String, Arc<dyn DnsProvider>> = HashMap::new();
    
    // Initialize Cloudflare DNS provider if configured
    if let Some(cf_token) = &config.cloudflare_api_token {
        match CloudflareDns::new(cf_token.clone()) {
            Ok(provider) => {
                info!("Initialized Cloudflare DNS provider");
                providers.insert("cloudflare".to_string(), Arc::new(provider));
            }
            Err(e) => {
                tracing::warn!("Failed to initialize Cloudflare DNS provider: {}", e);
            }
        }
    }
    
    // Initialize PowerDNS provider if configured
    if let (Some(pdns_url), Some(pdns_key)) = (&config.powerdns_api_url, &config.powerdns_api_key) {
        match PowerDns::new(pdns_key.clone(), pdns_url.clone(), None) {
            Ok(provider) => {
                info!("Initialized PowerDNS provider");
                providers.insert("powerdns".to_string(), Arc::new(provider));
            }
            Err(e) => {
                tracing::warn!("Failed to initialize PowerDNS provider: {}", e);
            }
        }
    }
    
    // Always add local DNS provider for testing/development
    match LocalDns::new("/tmp/ghostcp-dns") {
        Ok(provider) => {
            info!("Initialized Local DNS provider");
            providers.insert("local".to_string(), Arc::new(provider));
        }
        Err(e) => {
            tracing::warn!("Failed to initialize Local DNS provider: {}", e);
        }
    }
    
    if providers.is_empty() {
        return Err(anyhow::anyhow!("No DNS providers could be initialized"));
    }
    
    info!("Initialized {} DNS providers: {:?}", providers.len(), providers.keys().collect::<Vec<_>>());
    Ok(providers)
}