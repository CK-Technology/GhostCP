use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_domains: u32,
    pub total_dns_zones: u32,
    pub total_mail_accounts: u32,
    pub total_databases: u32,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub cpu_usage_percent: f32,
    pub load_average: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub is_running: bool,
    pub cpu_usage: Option<f32>,
    pub memory_usage_mb: Option<u64>,
    pub uptime_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemJob {
    pub id: String,
    pub job_type: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub role: String,
    pub package_name: String,
    pub disk_quota: u64,
    pub bandwidth_quota: u64,
    pub web_domains_limit: u32,
    pub dns_domains_limit: u32,
    pub mail_domains_limit: u32,
    pub databases_limit: u32,
    pub cron_jobs_limit: u32,
    pub disk_used: u64,
    pub bandwidth_used: u64,
    pub web_domains_count: u32,
    pub dns_domains_count: u32,
    pub mail_domains_count: u32,
    pub databases_count: u32,
    pub cron_jobs_count: u32,
    pub is_active: bool,
    pub is_suspended: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub ip_address: String,
    pub ipv6_address: Option<String>,
    pub web_template: String,
    pub backend_template: String,
    pub proxy_template: Option<String>,
    pub document_root: String,
    pub ssl_enabled: bool,
    pub ssl_force: bool,
    pub ssl_hsts: bool,
    pub letsencrypt_enabled: bool,
    pub letsencrypt_wildcard: bool,
    pub aliases: Vec<String>,
    pub bandwidth_used: u64,
    pub is_active: bool,
    pub is_suspended: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: u32,
    pub refresh_interval: u32,
    pub retry_interval: u32,
    pub expire_interval: u32,
    pub minimum_ttl: u32,
    pub dns_provider: String,
    pub provider_zone_id: Option<String>,
    pub dnssec_enabled: bool,
    pub template: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub priority: u16,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub dkim_enabled: bool,
    pub dkim_selector: String,
    pub dkim_public_key: Option<String>,
    pub antispam_enabled: bool,
    pub antivirus_enabled: bool,
    pub catchall_enabled: bool,
    pub rate_limit: u32,
    pub ssl_enabled: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificate {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub issuer: String,
    pub subject: String,
    pub san_domains: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub acme_provider: String,
    pub acme_challenge_type: String,
    pub auto_renew: bool,
    pub is_active: bool,
    pub is_wildcard: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Request types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub package_name: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub ip_address: String,
    pub web_template: String,
    pub backend_template: String,
    pub aliases: Option<Vec<String>>,
    pub ssl_enabled: bool,
    pub letsencrypt_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDnsZoneRequest {
    pub domain: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub dns_provider: String,
    pub dnssec_enabled: bool,
    pub template: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDnsRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u16>,
}