use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum UserRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "reseller")]
    Reseller,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::User => write!(f, "user"),
            UserRole::Reseller => write!(f, "reseller"),
        }
    }
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub full_name: Option<String>,
    
    // Package and quotas
    pub package_name: String,
    pub role: UserRole,
    
    // Quotas and limits
    pub disk_quota: i64,
    pub bandwidth_quota: i64,
    pub web_domains_limit: i32,
    pub dns_domains_limit: i32,
    pub mail_domains_limit: i32,
    pub databases_limit: i32,
    pub cron_jobs_limit: i32,
    
    // Usage counters
    pub disk_used: i64,
    pub bandwidth_used: i64,
    pub web_domains_count: i32,
    pub dns_domains_count: i32,
    pub mail_domains_count: i32,
    pub databases_count: i32,
    pub cron_jobs_count: i32,
    
    // System settings
    pub shell: String,
    pub home_dir: Option<String>,
    pub language: String,
    pub timezone: String,
    
    // Status and suspension
    pub is_active: bool,
    pub is_suspended: bool,
    pub suspended_reason: Option<String>,
    pub suspended_web: bool,
    pub suspended_dns: bool,
    pub suspended_mail: bool,
    pub suspended_db: bool,
    pub suspended_cron: bool,
    
    // Auth and security
    #[serde(skip_serializing)]
    pub two_factor_secret: Option<String>,
    #[serde(skip_serializing)]
    pub recovery_key: Option<String>,
    pub login_disabled: bool,
    pub allowed_ips: Option<Vec<String>>,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub package_name: Option<String>,
    pub role: Option<UserRole>,
    
    // Optional quota overrides
    pub disk_quota: Option<i64>,
    pub bandwidth_quota: Option<i64>,
    pub web_domains_limit: Option<i32>,
    pub dns_domains_limit: Option<i32>,
    pub mail_domains_limit: Option<i32>,
    pub databases_limit: Option<i32>,
    pub cron_jobs_limit: Option<i32>,
    
    // System settings
    pub shell: Option<String>,
    pub language: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub package_name: Option<String>,
    
    // Quota updates
    pub disk_quota: Option<i64>,
    pub bandwidth_quota: Option<i64>,
    pub web_domains_limit: Option<i32>,
    pub dns_domains_limit: Option<i32>,
    pub mail_domains_limit: Option<i32>,
    pub databases_limit: Option<i32>,
    pub cron_jobs_limit: Option<i32>,
    
    // System settings
    pub shell: Option<String>,
    pub language: Option<String>,
    pub timezone: Option<String>,
    
    // Status updates
    pub is_active: Option<bool>,
    pub is_suspended: Option<bool>,
    pub suspended_reason: Option<String>,
    pub suspended_web: Option<bool>,
    pub suspended_dns: Option<bool>,
    pub suspended_mail: Option<bool>,
    pub suspended_db: Option<bool>,
    pub suspended_cron: Option<bool>,
    
    // Security
    pub login_disabled: Option<bool>,
    pub allowed_ips: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub two_factor_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user: User,
}

impl User {
    pub fn can_create_web_domain(&self) -> bool {
        !self.is_suspended 
            && !self.suspended_web 
            && (self.web_domains_limit == 0 || self.web_domains_count < self.web_domains_limit)
    }
    
    pub fn can_create_dns_zone(&self) -> bool {
        !self.is_suspended 
            && !self.suspended_dns 
            && (self.dns_domains_limit == 0 || self.dns_domains_count < self.dns_domains_limit)
    }
    
    pub fn can_create_mail_domain(&self) -> bool {
        !self.is_suspended 
            && !self.suspended_mail 
            && (self.mail_domains_limit == 0 || self.mail_domains_count < self.mail_domains_limit)
    }
    
    pub fn can_create_database(&self) -> bool {
        !self.is_suspended 
            && !self.suspended_db 
            && (self.databases_limit == 0 || self.databases_count < self.databases_limit)
    }
    
    pub fn can_create_cron_job(&self) -> bool {
        !self.is_suspended 
            && !self.suspended_cron 
            && (self.cron_jobs_limit == 0 || self.cron_jobs_count < self.cron_jobs_limit)
    }
    
    pub fn is_within_disk_quota(&self, additional_mb: i64) -> bool {
        self.disk_quota == 0 || (self.disk_used + additional_mb) <= self.disk_quota
    }
    
    pub fn is_within_bandwidth_quota(&self, additional_mb: i64) -> bool {
        self.bandwidth_quota == 0 || (self.bandwidth_used + additional_mb) <= self.bandwidth_quota
    }
    
    pub fn has_admin_access(&self) -> bool {
        matches!(self.role, UserRole::Admin)
    }
    
    pub fn can_manage_user(&self, target_user: &User) -> bool {
        match self.role {
            UserRole::Admin => true,
            UserRole::Reseller => {
                // Resellers can manage regular users created by them
                matches!(target_user.role, UserRole::User) 
                    && target_user.created_by == Some(self.id)
            },
            UserRole::User => {
                // Users can only manage themselves
                self.id == target_user.id
            }
        }
    }
}