use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct Database {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,

    // `type` is a Rust keyword and a Postgres column; map it explicitly.
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub db_type: String,

    // Connection details
    pub host: String,
    pub port: Option<i32>,
    pub charset: String,

    // Size and limits
    pub size_mb: i64,

    // Status
    pub is_active: bool,
    pub is_suspended: bool,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDatabaseRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub db_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub charset: Option<String>,
}

impl Database {
    /// Default listening port for the engine when none is stored.
    pub fn default_port(db_type: &str) -> i32 {
        match db_type {
            "mysql" | "mariadb" => 3306,
            _ => 5432, // postgresql
        }
    }
}
