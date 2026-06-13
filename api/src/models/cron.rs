use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct CronJob {
    pub id: Uuid,
    pub user_id: Uuid,

    // Cron schedule fields
    pub minute: String,
    pub hour: String,
    pub day: String,
    pub month: String,
    pub weekday: String,

    // Command and execution
    pub command: String,
    pub working_directory: Option<String>,

    // Logging and notifications
    pub log_output: bool,
    pub email_output: bool,

    // Status and metadata
    pub is_active: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub run_count: i32,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCronJobRequest {
    pub command: String,
    pub minute: Option<String>,
    pub hour: Option<String>,
    pub day: Option<String>,
    pub month: Option<String>,
    pub weekday: Option<String>,
    pub working_directory: Option<String>,
    pub log_output: Option<bool>,
    pub email_output: Option<bool>,
}

impl CronJob {
    /// Render the five-field cron schedule (minute hour day month weekday).
    pub fn schedule_expression(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.minute, self.hour, self.day, self.month, self.weekday
        )
    }
}
