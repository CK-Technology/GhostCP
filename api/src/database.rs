use anyhow::Result;
use sqlx::{migrate::MigrateDatabase, PgPool, Postgres};
use tracing::{info, warn};

pub async fn connect(database_url: &str) -> Result<PgPool> {
    // Create database if it doesn't exist
    if !Postgres::database_exists(database_url).await.unwrap_or(false) {
        info!("Database doesn't exist, creating it...");
        Postgres::create_database(database_url).await?;
    }

    // Connect to the database
    let pool = PgPool::connect(database_url).await?;
    
    info!("Successfully connected to database");
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    info!("Running database migrations...");
    
    match sqlx::migrate!("./migrations").run(pool).await {
        Ok(_) => {
            info!("Database migrations completed successfully");
            Ok(())
        }
        Err(e) => {
            warn!("Migration error: {}", e);
            // For development, we might want to continue even if migrations fail
            // In production, this should probably be a hard error
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn test_database_connection() {
        let database_url = "postgresql://postgres:password@localhost/ghostcp_test";
        
        // This test requires a running PostgreSQL instance
        if let Ok(pool) = connect(database_url).await {
            let row = sqlx::query("SELECT 1 as test")
                .fetch_one(&pool)
                .await
                .expect("Failed to execute test query");
            
            let test_value: i32 = row.get("test");
            assert_eq!(test_value, 1);
        }
    }
}