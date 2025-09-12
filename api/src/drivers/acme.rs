use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME API error: {0}")]
    ApiError(String),
    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),
    #[error("Certificate generation failed: {0}")]
    CertificateError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub domains: Vec<String>,
    pub challenge_type: ChallengeType,
    pub key_type: KeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Http01,
    Dns01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

#[async_trait]
pub trait AcmeProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    
    async fn request_certificate(&self, request: &CertificateRequest) -> Result<String, AcmeError>;
    
    async fn renew_certificate(&self, cert_id: &str) -> Result<String, AcmeError>;
    
    async fn revoke_certificate(&self, cert_id: &str) -> Result<(), AcmeError>;
}

// TODO: Implement LetsEncrypt, ZeroSSL, BuyPass providers