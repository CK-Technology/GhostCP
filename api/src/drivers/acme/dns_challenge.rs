use super::{AcmeError, ChallengeHandler};
use crate::drivers::dns::DnsProvider;
use async_trait::async_trait;
use std::sync::Arc;

pub struct DnsChallenge {
    dns_provider: Arc<dyn DnsProvider>,
}

impl DnsChallenge {
    pub fn new(dns_provider: Arc<dyn DnsProvider>) -> Self {
        Self { dns_provider }
    }

    fn get_challenge_domain(domain: &str) -> String {
        format!("_acme-challenge.{}", domain)
    }

    fn calculate_key_authorization(token: &str, account_key_thumbprint: &str) -> String {
        // In a real implementation, this would calculate the SHA256 hash
        // of the JWK thumbprint concatenated with the token
        format!("{}.{}", token, account_key_thumbprint)
    }

    fn get_dns_txt_value(key_auth: &str) -> String {
        // Calculate SHA256 hash of key authorization and base64 encode it
        // This is a simplified implementation
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key_auth.hash(&mut hasher);
        let hash = hasher.finish();

        base64::encode(hash.to_string().as_bytes())
    }
}

#[async_trait]
impl ChallengeHandler for DnsChallenge {
    async fn setup_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<(), AcmeError> {
        let challenge_domain = Self::get_challenge_domain(domain);
        let txt_value = Self::get_dns_txt_value(key_auth);

        // Create TXT record for the challenge
        self.dns_provider
            .create_record(&challenge_domain, "TXT", &txt_value, 300)
            .await
            .map_err(|e| AcmeError::DnsChallenge(format!("Failed to create DNS record: {}", e)))?;

        // Wait for DNS propagation
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        tracing::info!(
            "DNS challenge set up for domain: {} with record: {} = {}",
            domain,
            challenge_domain,
            txt_value
        );

        Ok(())
    }

    async fn cleanup_challenge(&self, domain: &str, token: &str) -> Result<(), AcmeError> {
        let challenge_domain = Self::get_challenge_domain(domain);

        // Delete the TXT record
        self.dns_provider
            .delete_record(&challenge_domain, "TXT")
            .await
            .map_err(|e| AcmeError::DnsChallenge(format!("Failed to delete DNS record: {}", e)))?;

        tracing::info!("DNS challenge cleaned up for domain: {}", domain);

        Ok(())
    }

    async fn verify_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<bool, AcmeError> {
        let challenge_domain = Self::get_challenge_domain(domain);
        let expected_value = Self::get_dns_txt_value(key_auth);

        // Query DNS to verify the record exists
        match self.dns_provider.get_record(&challenge_domain, "TXT").await {
            Ok(records) => {
                let found = records.iter().any(|record| record.value == expected_value);
                if found {
                    tracing::info!("DNS challenge verified for domain: {}", domain);
                    Ok(true)
                } else {
                    tracing::warn!("DNS challenge not found for domain: {}", domain);
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("Failed to verify DNS challenge for domain {}: {}", domain, e);
                Err(AcmeError::DnsChallenge(format!("DNS verification failed: {}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_domain() {
        assert_eq!(
            DnsChallenge::get_challenge_domain("example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            DnsChallenge::get_challenge_domain("sub.example.com"),
            "_acme-challenge.sub.example.com"
        );
    }

    #[test]
    fn test_key_authorization() {
        let token = "test_token";
        let thumbprint = "test_thumbprint";
        let key_auth = DnsChallenge::calculate_key_authorization(token, thumbprint);
        assert_eq!(key_auth, "test_token.test_thumbprint");
    }

    #[test]
    fn test_dns_txt_value() {
        let key_auth = "test_key_auth";
        let txt_value = DnsChallenge::get_dns_txt_value(key_auth);
        assert!(!txt_value.is_empty());
        // The actual value would depend on the hash implementation
    }
}