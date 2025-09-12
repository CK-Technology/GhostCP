// Shared type definitions
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// Re-export common types
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;

// User types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserStatus {
    Active,
    Suspended,
    Inactive,
}

// Web domain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub document_root: String,
    pub php_enabled: bool,
    pub php_version: Option<String>,
    pub ssl_enabled: bool,
    pub ssl_force: bool,
    pub status: DomainStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainStatus {
    Active,
    Suspended,
    Inactive,
}

// DNS types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub provider: String,
    pub provider_zone_id: Option<String>,
    pub status: DnsStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub name: String,
    pub record_type: DnsRecordType,
    pub content: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    PTR,
    SRV,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsStatus {
    Active,
    Pending,
    Error,
}

// Mail types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub status: DomainStatus,
    pub dkim_enabled: bool,
    pub dkim_selector: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailAccount {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub username: String,
    pub quota: Option<i64>,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Database types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub db_type: DatabaseType,
    pub status: DatabaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MariaDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseStatus {
    Active,
    Inactive,
    Creating,
    Error,
}

// SSL Certificate types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificate {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub certificate_type: CertificateType,
    pub provider: String,
    pub status: CertificateStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateType {
    LetsEncrypt,
    SelfSigned,
    Uploaded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateStatus {
    Active,
    Pending,
    Expired,
    Error,
}

// System Job types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemJob {
    pub id: Uuid,
    pub job_type: String,
    pub status: JobStatus,
    pub progress: i32,
    pub message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

// API Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub total_pages: i32,
}

// Form types for creation/updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWebDomainRequest {
    pub domain: String,
    pub document_root: String,
    pub php_enabled: bool,
    pub php_version: Option<String>,
    pub ssl_enabled: bool,
    pub ssl_force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDnsZoneRequest {
    pub domain: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDnsRecordRequest {
    pub name: String,
    pub record_type: DnsRecordType,
    pub content: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMailDomainRequest {
    pub domain: String,
    pub dkim_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMailAccountRequest {
    pub username: String,
    pub password: String,
    pub quota: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatabaseRequest {
    pub name: String,
    pub db_type: DatabaseType,
    pub username: String,
    pub password: String,
}