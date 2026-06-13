use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct MailDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,

    // DKIM configuration
    pub dkim_enabled: bool,
    pub dkim_selector: String,
    #[serde(skip_serializing)]
    pub dkim_private_key: Option<String>,
    pub dkim_public_key: Option<String>,

    // Anti-spam and virus
    pub antispam_enabled: bool,
    pub antivirus_enabled: bool,

    // Catchall and forwarding
    pub catchall_enabled: bool,
    pub catchall_destination: Option<String>,

    // Rate limiting
    pub rate_limit: i32,

    // SSL/TLS
    pub ssl_enabled: bool,
    pub ssl_cert_path: Option<String>,
    pub ssl_key_path: Option<String>,

    // Status
    pub is_active: bool,
    pub is_suspended: bool,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct MailAccount {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub username: String,
    pub email: String,

    #[serde(skip_serializing)]
    pub password_hash: String,

    // Quotas and limits
    pub quota_mb: i32,
    pub disk_used_mb: i32,

    // Features
    pub forward_to: Option<Vec<String>>,
    pub forward_only: bool,
    pub autoreply_enabled: bool,
    pub autoreply_message: Option<String>,
    pub autoreply_subject: Option<String>,

    // Status
    pub is_active: bool,
    pub is_suspended: bool,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMailDomainRequest {
    pub domain: String,
    pub dkim_enabled: Option<bool>,
    pub dkim_selector: Option<String>,
    pub antispam_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub catchall_enabled: Option<bool>,
    pub catchall_destination: Option<String>,
    pub rate_limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMailAccountRequest {
    pub username: String,
    pub password: String,
    pub quota_mb: Option<i32>,
    pub forward_to: Option<Vec<String>>,
    pub forward_only: Option<bool>,
}
