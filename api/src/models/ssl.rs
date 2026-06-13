use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SslCertificate {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,

    // Certificate data
    pub certificate_pem: String,
    #[serde(skip_serializing)]
    pub private_key_pem: String,
    pub certificate_chain_pem: Option<String>,

    // Certificate metadata
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub san_domains: Option<Vec<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,

    // ACME / Let's Encrypt
    pub acme_provider: Option<String>,
    pub acme_challenge_type: Option<String>,
    pub acme_account_key_id: Option<String>,

    // Auto-renewal
    pub auto_renew: bool,
    pub renew_days_before: i32,

    // Status
    pub is_active: bool,
    pub is_wildcard: bool,

    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to provision a certificate.
///
/// Two modes are supported:
/// * Manual upload — supply `certificate_pem` and `private_key_pem`.
/// * ACME issuance — omit the PEM fields and set `acme_provider`/
///   `acme_challenge_type`; the row is stored inactive and picked up by the
///   ACME job runner for issuance.
#[derive(Debug, Deserialize)]
pub struct RequestCertificateRequest {
    pub domain: String,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub certificate_chain_pem: Option<String>,
    pub acme_provider: Option<String>,
    pub acme_challenge_type: Option<String>,
    pub san_domains: Option<Vec<String>>,
    pub is_wildcard: Option<bool>,
    pub auto_renew: Option<bool>,
}

impl SslCertificate {
    /// Whether the certificate is past its renewal threshold.
    pub fn needs_renewal(&self, now: DateTime<Utc>) -> bool {
        match self.valid_until {
            Some(valid_until) => {
                let threshold = chrono::Duration::days(self.renew_days_before as i64);
                now + threshold >= valid_until
            }
            None => true,
        }
    }
}
