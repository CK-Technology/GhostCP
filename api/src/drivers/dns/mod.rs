pub mod cloudflare;
pub mod powerdns;
pub mod local;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use crate::models::{DnsZone as DbDnsZone, DnsRecord as DbDnsRecord};

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Zone not found: {zone}")]
    ZoneNotFound { zone: String },
    #[error("Record not found: {record_id}")]
    RecordNotFound { record_id: String },
    #[error("Invalid record type: {record_type}")]
    InvalidRecordType { record_type: String },
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub id: Option<String>,
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub dnssec_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Option<String>,
    pub zone_id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub proxied: Option<bool>, // Cloudflare specific
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub name_servers: Vec<String>,
    pub dnssec_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub provider_type: String,
    pub api_endpoint: Option<String>,
    pub api_token: Option<String>,
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub zone_id: Option<String>,
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Get provider name
    fn provider_name(&self) -> &'static str;
    
    /// Test connectivity and authentication
    async fn health_check(&self) -> Result<(), DnsError>;
    
    /// Create a new DNS zone
    async fn create_zone(&self, zone: &DnsZone) -> Result<DnsZoneInfo, DnsError>;
    
    /// Get zone information
    async fn get_zone(&self, zone_id: &str) -> Result<DnsZoneInfo, DnsError>;
    
    /// List all zones
    async fn list_zones(&self) -> Result<Vec<DnsZoneInfo>, DnsError>;
    
    /// Update zone settings
    async fn update_zone(&self, zone_id: &str, zone: &DnsZone) -> Result<(), DnsError>;
    
    /// Delete a zone
    async fn delete_zone(&self, zone_id: &str) -> Result<(), DnsError>;
    
    /// Create a DNS record
    async fn create_record(&self, record: &DnsRecord) -> Result<String, DnsError>;
    
    /// Get a DNS record
    async fn get_record(&self, zone_id: &str, record_id: &str) -> Result<DnsRecord, DnsError>;
    
    /// List records in a zone
    async fn list_records(&self, zone_id: &str, record_type: Option<&str>) -> Result<Vec<DnsRecord>, DnsError>;
    
    /// Update a DNS record
    async fn update_record(&self, record_id: &str, record: &DnsRecord) -> Result<(), DnsError>;
    
    /// Delete a DNS record
    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), DnsError>;
    
    /// Enable/disable DNSSEC for a zone
    async fn set_dnssec(&self, zone_id: &str, enabled: bool) -> Result<(), DnsError>;
    
    /// Get DNSSEC keys for a zone
    async fn get_dnssec_keys(&self, zone_id: &str) -> Result<Vec<DnssecKey>, DnsError>;
    
    /// Import zone from file/text
    async fn import_zone(&self, zone_id: &str, zone_file: &str) -> Result<(), DnsError>;
    
    /// Export zone to file/text
    async fn export_zone(&self, zone_id: &str) -> Result<String, DnsError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKey {
    pub id: String,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    pub public_key: String,
    pub key_type: String, // KSK or ZSK
}

// Utility functions for converting between our models and provider models
impl From<&DbDnsZone> for DnsZone {
    fn from(db_zone: &DbDnsZone) -> Self {
        DnsZone {
            id: db_zone.provider_zone_id.clone(),
            name: db_zone.domain.clone(),
            primary_ns: db_zone.primary_ns.clone(),
            admin_email: db_zone.admin_email.clone(),
            serial: db_zone.serial as u32,
            refresh: db_zone.refresh_interval as u32,
            retry: db_zone.retry_interval as u32,
            expire: db_zone.expire_interval as u32,
            minimum: db_zone.minimum_ttl as u32,
            dnssec_enabled: db_zone.dnssec_enabled,
        }
    }
}

impl From<&DbDnsRecord> for DnsRecord {
    fn from(db_record: &DbDnsRecord) -> Self {
        DnsRecord {
            id: Some(db_record.id.to_string()),
            zone_id: db_record.zone_id.to_string(),
            name: db_record.name.clone(),
            record_type: db_record.record_type.clone(),
            content: db_record.value.clone(),
            ttl: db_record.ttl as u32,
            priority: if db_record.priority > 0 { Some(db_record.priority as u16) } else { None },
            proxied: None, // Set by specific provider implementations
        }
    }
}

// Standard DNS record types
pub const DNS_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA"
];

pub fn validate_record_type(record_type: &str) -> Result<(), DnsError> {
    if DNS_RECORD_TYPES.contains(&record_type) {
        Ok(())
    } else {
        Err(DnsError::InvalidRecordType { 
            record_type: record_type.to_string() 
        })
    }
}