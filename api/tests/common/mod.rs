use ghostcp_api::{config::Config, initialize_dns_providers, AppState};
use sqlx::{Executor, PgPool};
use std::sync::Arc;
use uuid::Uuid;

/// Shared fixture for integration tests that need a live database and a fully
/// constructed `AppState`. Tests using this require a reachable PostgreSQL
/// instance via `DATABASE_URL`, so they are gated behind `#[ignore]` and run
/// explicitly with `cargo test -- --ignored`.
pub struct TestContext {
    pub app_state: AppState,
    pub db: PgPool,
    pub test_user_id: Uuid,
}

impl TestContext {
    pub async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://ghostcp:password@localhost/ghostcp".to_string());

        let db = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        // Ensure the schema is present.
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("Failed to run migrations");

        // SAFETY: tests are single-threaded per process for env mutation here.
        unsafe {
            std::env::set_var("DATABASE_URL", &database_url);
        }
        let config = Config::from_env().expect("Failed to build config from env");

        let dns_providers = Arc::new(
            initialize_dns_providers(&config)
                .await
                .expect("Failed to initialize DNS providers"),
        );

        let app_state = AppState {
            db: db.clone(),
            config,
            dns_providers,
        };

        let test_user_id = create_test_user(&db).await;

        Self {
            app_state,
            db,
            test_user_id,
        }
    }

    pub async fn cleanup(&self) {
        let _ = self
            .db
            .execute("TRUNCATE users, web_domains, dns_zones, dns_records, mail_domains, databases CASCADE")
            .await;
    }
}

async fn create_test_user(db: &PgPool) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(user_id)
    .bind("testuser")
    .bind("test@example.com")
    .bind("$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash")
    .bind("user")
    .execute(db)
    .await
    .expect("Failed to create test user");

    user_id
}

#[macro_export]
macro_rules! test_with_context {
    ($test_name:ident, $ctx:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires a reachable PostgreSQL instance (DATABASE_URL)"]
        async fn $test_name() {
            let $ctx = $crate::common::TestContext::new().await;
            $body
            $ctx.cleanup().await;
        }
    };
}
