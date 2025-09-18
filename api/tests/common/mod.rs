use ghostcp_api::{AppState, config::Config};
use sqlx::{PgPool, Executor};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct TestContext {
    pub app_state: AppState,
    pub db: PgPool,
    pub test_user_id: Uuid,
}

impl TestContext {
    pub async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://ghostcp_test:test_password@localhost:5433/ghostcp_test".to_string());

        let db = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("Failed to run migrations");

        let config = Config {
            database_url: database_url.clone(),
            jwt_secret: "test_secret".to_string(),
            redis_url: "redis://localhost:6380".to_string(),
            bind_address: "127.0.0.1:8080".to_string(),
            ..Default::default()
        };

        let dns_providers = Arc::new(HashMap::new());

        let app_state = AppState {
            db: db.clone(),
            config,
            dns_providers,
        };

        // Create test user
        let test_user_id = create_test_user(&db).await;

        Self {
            app_state,
            db,
            test_user_id,
        }
    }

    pub async fn cleanup(&self) {
        // Clean up test data
        let _ = self.db.execute("TRUNCATE users, web_domains, dns_zones, dns_records, mail_domains, databases CASCADE").await;
    }
}

async fn create_test_user(db: &PgPool) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)",
        user_id,
        "testuser",
        "test@example.com",
        "$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash",
        "user"
    )
    .execute(db)
    .await
    .expect("Failed to create test user");

    user_id
}

#[macro_export]
macro_rules! test_with_context {
    ($test_name:ident, $test_fn:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let ctx = crate::common::TestContext::new().await;

            let result = $test_fn(&ctx).await;

            ctx.cleanup().await;

            result
        }
    };
}