pub mod letsencrypt;
pub mod dns_challenge;
pub mod http_challenge;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("DNS challenge failed: {0}")]
    DnsChallenge(String),
    #[error("HTTP challenge failed: {0}")]
    HttpChallenge(String),
    #[error("Certificate generation failed: {0}")]
    CertificateGeneration(String),
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    #[error("Rate limit exceeded")]
    RateLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub domain: String,
    pub san_domains: Vec<String>,
    pub challenge_type: ChallengeType,
    pub auto_renew: bool,
    pub key_type: KeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_chain_pem: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
    pub issuer: String,
    pub serial_number: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    pub email: String,
    pub private_key_pem: String,
    pub account_url: String,
    pub terms_agreed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_type: ChallengeType,
    pub token: String,
    pub url: String,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
    Expired,
}

#[async_trait]
pub trait AcmeProvider: Send + Sync {
    /// Initialize the ACME provider with configuration
    async fn initialize(&self, config: &HashMap<String, String>) -> Result<(), AcmeError>;

    /// Create or get existing ACME account
    async fn get_or_create_account(&self, email: &str) -> Result<AcmeAccount, AcmeError>;

    /// Request a new certificate
    async fn request_certificate(&self, request: &CertificateRequest) -> Result<Certificate, AcmeError>;

    /// Renew an existing certificate
    async fn renew_certificate(&self, certificate_id: Uuid) -> Result<Certificate, AcmeError>;

    /// Revoke a certificate
    async fn revoke_certificate(&self, certificate_id: Uuid) -> Result<(), AcmeError>;

    /// Check if certificate needs renewal (typically 30 days before expiry)
    async fn needs_renewal(&self, certificate: &Certificate) -> bool;

    /// Validate domain ownership via challenge
    async fn validate_challenge(&self, challenge: &Challenge) -> Result<bool, AcmeError>;
}

#[async_trait]
pub trait ChallengeHandler: Send + Sync {
    /// Setup the challenge for domain validation
    async fn setup_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<(), AcmeError>;

    /// Cleanup the challenge after validation
    async fn cleanup_challenge(&self, domain: &str, token: &str) -> Result<(), AcmeError>;

    /// Verify that the challenge is properly set up
    async fn verify_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<bool, AcmeError>;
}

pub struct AcmeManager {
    providers: HashMap<String, Box<dyn AcmeProvider>>,
    challenge_handlers: HashMap<ChallengeType, Box<dyn ChallengeHandler>>,
}

impl AcmeManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            challenge_handlers: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, name: String, provider: Box<dyn AcmeProvider>) {
        self.providers.insert(name, provider);
    }

    pub fn add_challenge_handler(&mut self, challenge_type: ChallengeType, handler: Box<dyn ChallengeHandler>) {
        self.challenge_handlers.insert(challenge_type, handler);
    }

    pub async fn request_certificate(
        &self,
        provider_name: &str,
        request: &CertificateRequest,
    ) -> Result<Certificate, AcmeError> {
        let provider = self.providers.get(provider_name)
            .ok_or_else(|| AcmeError::Configuration(format!("Provider {} not found", provider_name)))?;

        // Setup challenge handler
        let challenge_handler = self.challenge_handlers.get(&request.challenge_type)
            .ok_or_else(|| AcmeError::Configuration(format!("Challenge handler for {:?} not found", request.challenge_type)))?;

        // Validate domains first
        for domain in std::iter::once(&request.domain).chain(request.san_domains.iter()) {
            if !Self::is_valid_domain(domain) {
                return Err(AcmeError::Configuration(format!("Invalid domain: {}", domain)));
            }
        }

        provider.request_certificate(request).await
    }

    pub async fn renew_certificate(
        &self,
        provider_name: &str,
        certificate_id: Uuid,
    ) -> Result<Certificate, AcmeError> {
        let provider = self.providers.get(provider_name)
            .ok_or_else(|| AcmeError::Configuration(format!("Provider {} not found", provider_name)))?;

        provider.renew_certificate(certificate_id).await
    }

    pub async fn auto_renew_certificates(&self) -> Result<Vec<Certificate>, AcmeError> {
        let mut renewed_certificates = Vec::new();

        // This would typically query the database for certificates that need renewal
        // For now, we'll return an empty vector
        Ok(renewed_certificates)
    }

    fn is_valid_domain(domain: &str) -> bool {
        // Basic domain validation
        !domain.is_empty() &&
        domain.len() <= 253 &&
        domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') &&
        !domain.starts_with('-') &&
        !domain.ends_with('-') &&
        domain.contains('.')
    }
}

impl Default for AcmeManager {
    fn default() -> Self {
        Self::new()
    }
}