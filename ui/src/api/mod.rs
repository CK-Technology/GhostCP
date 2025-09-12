// API client for interacting with GhostCP backend
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "ssr")]
use reqwest;

#[cfg(not(feature = "ssr"))]
use gloo_net::http::Request;

pub struct ApiClient {
    base_url: String,
    #[cfg(feature = "ssr")]
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            #[cfg(feature = "ssr")]
            client: reqwest::Client::new(),
        }
    }

    // User endpoints
    pub async fn list_users(&self) -> Result<PaginatedResponse<User>, ApiError> {
        self.get("/api/v1/users").await
    }

    pub async fn get_user(&self, id: uuid::Uuid) -> Result<User, ApiError> {
        self.get(&format!("/api/v1/users/{}", id)).await
    }

    pub async fn create_user(&self, user_data: CreateUserRequest) -> Result<User, ApiError> {
        self.post("/api/v1/users", user_data).await
    }

    // Web domain endpoints
    pub async fn list_web_domains(&self) -> Result<PaginatedResponse<WebDomain>, ApiError> {
        self.get("/api/v1/domains").await
    }

    pub async fn get_web_domain(&self, id: uuid::Uuid) -> Result<WebDomain, ApiError> {
        self.get(&format!("/api/v1/domains/{}", id)).await
    }

    pub async fn create_web_domain(&self, domain_data: CreateWebDomainRequest) -> Result<WebDomain, ApiError> {
        self.post("/api/v1/domains", domain_data).await
    }

    // DNS endpoints
    pub async fn list_dns_zones(&self) -> Result<PaginatedResponse<DnsZone>, ApiError> {
        self.get("/api/v1/dns").await
    }

    pub async fn get_dns_zone(&self, id: uuid::Uuid) -> Result<DnsZone, ApiError> {
        self.get(&format!("/api/v1/dns/{}", id)).await
    }

    pub async fn create_dns_zone(&self, zone_data: CreateDnsZoneRequest) -> Result<DnsZone, ApiError> {
        self.post("/api/v1/dns", zone_data).await
    }

    pub async fn list_dns_records(&self, zone_id: uuid::Uuid) -> Result<PaginatedResponse<DnsRecord>, ApiError> {
        self.get(&format!("/api/v1/dns/{}/records", zone_id)).await
    }

    pub async fn create_dns_record(&self, zone_id: uuid::Uuid, record_data: CreateDnsRecordRequest) -> Result<DnsRecord, ApiError> {
        self.post(&format!("/api/v1/dns/{}/records", zone_id), record_data).await
    }

    // Mail endpoints
    pub async fn list_mail_domains(&self) -> Result<PaginatedResponse<MailDomain>, ApiError> {
        self.get("/api/v1/mail").await
    }

    pub async fn create_mail_domain(&self, domain_data: CreateMailDomainRequest) -> Result<MailDomain, ApiError> {
        self.post("/api/v1/mail", domain_data).await
    }

    pub async fn list_mail_accounts(&self, domain_id: uuid::Uuid) -> Result<PaginatedResponse<MailAccount>, ApiError> {
        self.get(&format!("/api/v1/mail/{}/accounts", domain_id)).await
    }

    pub async fn create_mail_account(&self, domain_id: uuid::Uuid, account_data: CreateMailAccountRequest) -> Result<MailAccount, ApiError> {
        self.post(&format!("/api/v1/mail/{}/accounts", domain_id), account_data).await
    }

    // Database endpoints
    pub async fn list_databases(&self) -> Result<PaginatedResponse<Database>, ApiError> {
        self.get("/api/v1/databases").await
    }

    pub async fn create_database(&self, db_data: CreateDatabaseRequest) -> Result<Database, ApiError> {
        self.post("/api/v1/databases", db_data).await
    }

    // SSL endpoints
    pub async fn list_certificates(&self) -> Result<PaginatedResponse<SslCertificate>, ApiError> {
        self.get("/api/v1/ssl").await
    }

    pub async fn request_certificate(&self, cert_data: RequestCertificateRequest) -> Result<SslCertificate, ApiError> {
        self.post("/api/v1/ssl", cert_data).await
    }

    // System job endpoints
    pub async fn list_system_jobs(&self) -> Result<PaginatedResponse<SystemJob>, ApiError> {
        self.get("/api/v1/jobs").await
    }

    // Generic HTTP methods
    async fn get<T>(&self, path: &str) -> Result<T, ApiError> 
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        
        #[cfg(feature = "ssr")]
        {
            let response = self.client.get(&url)
                .send()
                .await
                .map_err(ApiError::Network)?;
                
            if !response.status().is_success() {
                return Err(ApiError::Http(response.status().as_u16()));
            }
            
            response.json().await.map_err(ApiError::Deserialization)
        }
        
        #[cfg(not(feature = "ssr"))]
        {
            let response = Request::get(&url)
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
                
            if !response.ok() {
                return Err(ApiError::Http(response.status()));
            }
            
            response.json().await.map_err(|e| ApiError::Deserialization(e.to_string()))
        }
    }

    async fn post<T, B>(&self, path: &str, body: B) -> Result<T, ApiError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let url = format!("{}{}", self.base_url, path);
        
        #[cfg(feature = "ssr")]
        {
            let response = self.client.post(&url)
                .json(&body)
                .send()
                .await
                .map_err(ApiError::Network)?;
                
            if !response.status().is_success() {
                return Err(ApiError::Http(response.status().as_u16()));
            }
            
            response.json().await.map_err(ApiError::Deserialization)
        }
        
        #[cfg(not(feature = "ssr"))]
        {
            let response = Request::post(&url)
                .json(&body)
                .map_err(|e| ApiError::Serialization(e.to_string()))?
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
                
            if !response.ok() {
                return Err(ApiError::Http(response.status()));
            }
            
            response.json().await.map_err(|e| ApiError::Deserialization(e.to_string()))
        }
    }
}

// Error types
#[derive(Debug, Clone)]
pub enum ApiError {
    #[cfg(feature = "ssr")]
    Network(reqwest::Error),
    #[cfg(not(feature = "ssr"))]
    Network(String),
    
    #[cfg(feature = "ssr")]
    Http(u16),
    #[cfg(not(feature = "ssr"))]
    Http(u16),
    
    #[cfg(feature = "ssr")]
    Serialization(serde_json::Error),
    #[cfg(not(feature = "ssr"))]
    Serialization(String),
    
    #[cfg(feature = "ssr")]
    Deserialization(reqwest::Error),
    #[cfg(not(feature = "ssr"))]
    Deserialization(String),
    
    Unknown(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Network(e) => write!(f, "Network error: {}", e),
            ApiError::Http(status) => write!(f, "HTTP error: {}", status),
            ApiError::Serialization(e) => write!(f, "Serialization error: {}", e),
            ApiError::Deserialization(e) => write!(f, "Deserialization error: {}", e),
            ApiError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

// Additional request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCertificateRequest {
    pub domain: String,
    pub certificate_type: CertificateType,
    pub provider: String,
}

// Global API client instance
static mut API_CLIENT: Option<ApiClient> = None;

pub fn init_api_client(base_url: String) {
    unsafe {
        API_CLIENT = Some(ApiClient::new(base_url));
    }
}

pub fn api_client() -> &'static ApiClient {
    unsafe {
        API_CLIENT.as_ref().expect("API client not initialized. Call init_api_client() first.")
    }
}