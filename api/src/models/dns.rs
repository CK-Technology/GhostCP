use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DnsZone {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    
    // SOA fields
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: i64,
    pub refresh_interval: i32,
    pub retry_interval: i32,
    pub expire_interval: i32,
    pub minimum_ttl: i32,
    
    // DNS provider and settings
    pub dns_provider: String, // local, cloudflare, powerdns, route53
    pub provider_zone_id: Option<String>,
    pub dnssec_enabled: bool,
    
    // Template and automation
    pub template: String,
    
    // Status
    pub is_active: bool,
    pub is_suspended: bool,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DnsRecord {
    pub id: Uuid,
    pub zone_id: Uuid,
    
    // Record data
    pub name: String,
    pub record_type: String, // A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR
    pub value: String,
    pub ttl: i32,
    pub priority: i32, // for MX, SRV records
    
    // Status
    pub is_active: bool,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDnsZoneRequest {
    pub domain: String,
    pub primary_ns: Option<String>,
    pub admin_email: Option<String>,
    pub template: Option<String>,
    pub dns_provider: Option<String>,
    pub dnssec_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDnsRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SRV,
    CAA,
    PTR,
}

impl DnsZone {
    pub fn increment_serial(&mut self) {
        // Use timestamp-based serial number (YYYYMMDDNN format)
        let now = Utc::now();
        let date_part = now.format("%Y%m%d").to_string().parse::<i64>().unwrap_or(0) * 100;
        
        if self.serial < date_part {
            self.serial = date_part + 1;
        } else {
            self.serial += 1;
        }
    }
    
    pub fn get_soa_record(&self) -> String {
        format!(
            "{domain} IN SOA {primary_ns} {admin_email} {serial} {refresh} {retry} {expire} {minimum}",
            domain = self.domain,
            primary_ns = self.primary_ns,
            admin_email = self.admin_email.replace('@', "."),
            serial = self.serial,
            refresh = self.refresh_interval,
            retry = self.retry_interval,
            expire = self.expire_interval,
            minimum = self.minimum_ttl
        )
    }
}