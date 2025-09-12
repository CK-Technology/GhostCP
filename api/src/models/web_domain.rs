use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct WebDomain {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    
    // IP and networking
    pub ip_address: Option<IpAddr>,
    pub ipv6_address: Option<IpAddr>,
    
    // Templates and configuration
    pub web_template: String,
    pub backend_template: String,
    pub proxy_template: Option<String>,
    pub proxy_extensions: Option<Vec<String>>,
    
    // Document root and paths
    pub document_root: Option<String>,
    
    // SSL/TLS features
    pub ssl_enabled: bool,
    pub ssl_cert_path: Option<String>,
    pub ssl_key_path: Option<String>,
    pub ssl_ca_path: Option<String>,
    pub ssl_force: bool,
    pub ssl_hsts: bool,
    pub letsencrypt_enabled: bool,
    pub letsencrypt_wildcard: bool,
    
    // Aliases and redirects
    pub aliases: Option<Vec<String>>,
    pub redirects: serde_json::Value, // JSONB array of redirect rules
    
    // Stats and usage
    pub bandwidth_used: i64,
    
    // Status
    pub is_active: bool,
    pub is_suspended: bool,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebDomainRequest {
    pub domain: String,
    pub ip_address: Option<IpAddr>,
    pub ipv6_address: Option<IpAddr>,
    pub web_template: Option<String>,
    pub backend_template: Option<String>,
    pub proxy_template: Option<String>,
    pub proxy_extensions: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    pub ssl_enabled: Option<bool>,
    pub letsencrypt_enabled: Option<bool>,
    pub letsencrypt_wildcard: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebDomainRequest {
    pub ip_address: Option<IpAddr>,
    pub ipv6_address: Option<IpAddr>,
    pub web_template: Option<String>,
    pub backend_template: Option<String>,
    pub proxy_template: Option<String>,
    pub proxy_extensions: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    pub ssl_enabled: Option<bool>,
    pub ssl_force: Option<bool>,
    pub ssl_hsts: Option<bool>,
    pub letsencrypt_enabled: Option<bool>,
    pub letsencrypt_wildcard: Option<bool>,
    pub redirects: Option<serde_json::Value>,
    pub is_active: Option<bool>,
    pub is_suspended: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct WebDomainStats {
    pub domain: String,
    pub bandwidth_used: i64,
    pub disk_used: i64,
    pub ssl_expires_at: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
}

impl WebDomain {
    pub fn get_document_root(&self) -> String {
        self.document_root
            .clone()
            .unwrap_or_else(|| format!("/home/{}/web/{}/public_html", self.user_id, self.domain))
    }
    
    pub fn get_ssl_cert_path(&self) -> String {
        self.ssl_cert_path
            .clone()
            .unwrap_or_else(|| format!("/etc/ghostcp/ssl/{}/cert.pem", self.domain))
    }
    
    pub fn get_ssl_key_path(&self) -> String {
        self.ssl_key_path
            .clone()
            .unwrap_or_else(|| format!("/etc/ghostcp/ssl/{}/private.key", self.domain))
    }
    
    pub fn get_all_domains(&self) -> Vec<String> {
        let mut domains = vec![self.domain.clone()];
        if let Some(aliases) = &self.aliases {
            domains.extend(aliases.iter().cloned());
        }
        domains
    }
    
    pub fn is_ssl_configured(&self) -> bool {
        self.ssl_enabled && 
        (self.ssl_cert_path.is_some() || self.letsencrypt_enabled)
    }
    
    pub fn requires_nginx_reload(&self, update: &UpdateWebDomainRequest) -> bool {
        // Check if any changes require NGINX reload
        update.web_template.is_some() ||
        update.backend_template.is_some() ||
        update.proxy_template.is_some() ||
        update.ssl_enabled.is_some() ||
        update.ssl_force.is_some() ||
        update.aliases.is_some() ||
        update.redirects.is_some()
    }
}