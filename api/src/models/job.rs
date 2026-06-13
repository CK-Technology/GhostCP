use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SystemJob {
    pub id: Uuid,
    pub job_type: String,
    pub user_id: Option<Uuid>,

    // Job configuration
    pub parameters: serde_json::Value,

    // Execution tracking
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,

    // Output and logging
    pub output_log: Option<String>,
    pub error_log: Option<String>,

    // Retry mechanism
    pub max_retries: i32,
    pub retry_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,

    // Priority and scheduling
    pub priority: i32,
    pub scheduled_for: DateTime<Utc>,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSystemJobRequest {
    pub job_type: String,
    pub parameters: Option<serde_json::Value>,
    pub priority: Option<i32>,
    pub max_retries: Option<i32>,
    pub scheduled_for: Option<DateTime<Utc>>,
}
