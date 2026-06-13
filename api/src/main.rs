use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ghostcp_api::{create_router, database, initialize_dns_providers, AppState};
use ghostcp_api::config::Config;

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
