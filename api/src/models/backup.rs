use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct BackupConfig {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,

    // Backup scope
    pub include_files: bool,
    pub include_databases: bool,
    pub include_mail: bool,

    // Specific inclusions/exclusions
    pub included_paths: Option<Vec<String>>,
    pub excluded_paths: Option<Vec<String>>,
    pub included_databases: Option<Vec<Uuid>>,

    // Storage backend (Restic-compatible)
    pub backend_type: String,
    pub backend_config: serde_json::Value,
    #[serde(skip_serializing)]
    pub repository_password: String,

    // Schedule
    pub schedule_cron: Option<String>,
    pub retention_policy: serde_json::Value,

    // Status
    pub is_active: bool,
    pub last_backup: Option<DateTime<Utc>>,
    pub next_backup: Option<DateTime<Utc>>,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBackupConfigRequest {
    pub name: String,
    pub backend_type: String,
    pub backend_config: serde_json::Value,
    pub repository_password: String,
    pub include_files: Option<bool>,
    pub include_databases: Option<bool>,
    pub include_mail: Option<bool>,
    pub included_paths: Option<Vec<String>>,
    pub excluded_paths: Option<Vec<String>>,
    pub included_databases: Option<Vec<Uuid>>,
    pub schedule_cron: Option<String>,
    pub retention_policy: Option<serde_json::Value>,
}
