use super::{AcmeError, ChallengeHandler};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct HttpChallenge {
    challenges: Arc<RwLock<HashMap<String, String>>>,
    webroot_path: String,
}

impl HttpChallenge {
    pub fn new(webroot_path: String) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            webroot_path,
        }
    }

    fn get_challenge_path(&self, token: &str) -> String {
        format!("{}/.well-known/acme-challenge/{}", self.webroot_path, token)
    }

    fn get_challenge_url(domain: &str, token: &str) -> String {
        format!("http://{}/.well-known/acme-challenge/{}", domain, token)
    }

    async fn write_challenge_file(&self, token: &str, key_auth: &str) -> Result<(), AcmeError> {
        let challenge_path = self.get_challenge_path(token);

        // Ensure the directory exists
        if let Some(parent) = std::path::Path::new(&challenge_path).parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AcmeError::HttpChallenge(format!("Failed to create challenge directory: {}", e)))?;
        }

        // Write the challenge file
        tokio::fs::write(&challenge_path, key_auth)
            .await
            .map_err(|e| AcmeError::HttpChallenge(format!("Failed to write challenge file: {}", e)))?;

        tracing::info!("HTTP challenge file written: {}", challenge_path);
        Ok(())
    }

    async fn remove_challenge_file(&self, token: &str) -> Result<(), AcmeError> {
        let challenge_path = self.get_challenge_path(token);

        if tokio::fs::metadata(&challenge_path).await.is_ok() {
            tokio::fs::remove_file(&challenge_path)
                .await
                .map_err(|e| AcmeError::HttpChallenge(format!("Failed to remove challenge file: {}", e)))?;

            tracing::info!("HTTP challenge file removed: {}", challenge_path);
        }

        Ok(())
    }

    async fn verify_challenge_url(&self, domain: &str, token: &str, expected_content: &str) -> Result<bool, AcmeError> {
        let challenge_url = Self::get_challenge_url(domain, token);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AcmeError::HttpChallenge(format!("Failed to create HTTP client: {}", e)))?;

        match client.get(&challenge_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(content) => {
                            let matches = content.trim() == expected_content;
                            if matches {
                                tracing::info!("HTTP challenge verified for domain: {}", domain);
                            } else {
                                tracing::warn!(
                                    "HTTP challenge content mismatch for domain: {}. Expected: {}, Got: {}",
                                    domain, expected_content, content
                                );
                            }
                            Ok(matches)
                        }
                        Err(e) => {
                            tracing::error!("Failed to read challenge response for domain {}: {}", domain, e);
                            Ok(false)
                        }
                    }
                } else {
                    tracing::warn!(
                        "HTTP challenge request failed for domain: {} with status: {}",
                        domain, response.status()
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("Failed to access challenge URL for domain {}: {}", domain, e);
                Ok(false)
            }
        }
    }
}

#[async_trait]
impl ChallengeHandler for HttpChallenge {
    async fn setup_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<(), AcmeError> {
        // Store the challenge in memory for serving via HTTP
        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(token.to_string(), key_auth.to_string());
        }

        // Also write to file system for nginx/apache serving
        self.write_challenge_file(token, key_auth).await?;

        tracing::info!(
            "HTTP challenge set up for domain: {} with token: {}",
            domain, token
        );

        Ok(())
    }

    async fn cleanup_challenge(&self, domain: &str, token: &str) -> Result<(), AcmeError> {
        // Remove from memory
        {
            let mut challenges = self.challenges.write().await;
            challenges.remove(token);
        }

        // Remove file
        self.remove_challenge_file(token).await?;

        tracing::info!("HTTP challenge cleaned up for domain: {} with token: {}", domain, token);

        Ok(())
    }

    async fn verify_challenge(&self, domain: &str, token: &str, key_auth: &str) -> Result<bool, AcmeError> {
        // First check if we have the challenge stored
        let has_challenge = {
            let challenges = self.challenges.read().await;
            challenges.get(token).map(|stored| stored == key_auth).unwrap_or(false)
        };

        if !has_challenge {
            tracing::warn!("Challenge not found in memory for domain: {}", domain);
            return Ok(false);
        }

        // Verify the challenge is accessible via HTTP
        self.verify_challenge_url(domain, token, key_auth).await
    }
}

// Helper function to serve challenges via axum/warp if needed
impl HttpChallenge {
    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).cloned()
    }

    pub fn create_challenge_routes() -> axum::Router {
        use axum::{extract::Path, response::Response, routing::get, Router};

        async fn serve_challenge(Path(token): Path<String>) -> Response<String> {
            // This would need access to the HttpChallenge instance
            // In a real implementation, you'd pass it through app state
            Response::builder()
                .status(404)
                .body("Challenge not found".to_string())
                .unwrap()
        }

        Router::new()
            .route("/.well-known/acme-challenge/:token", get(serve_challenge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_http_challenge_setup_and_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let webroot_path = temp_dir.path().to_string_lossy().to_string();

        let challenge = HttpChallenge::new(webroot_path);
        let domain = "example.com";
        let token = "test_token";
        let key_auth = "test_key_auth";

        // Test setup
        assert!(challenge.setup_challenge(domain, token, key_auth).await.is_ok());

        // Verify challenge is stored in memory
        {
            let challenges = challenge.challenges.read().await;
            assert_eq!(challenges.get(token), Some(&key_auth.to_string()));
        }

        // Test cleanup
        assert!(challenge.cleanup_challenge(domain, token).await.is_ok());

        // Verify challenge is removed from memory
        {
            let challenges = challenge.challenges.read().await;
            assert!(!challenges.contains_key(token));
        }
    }

    #[test]
    fn test_challenge_path() {
        let challenge = HttpChallenge::new("/var/www/html".to_string());
        let token = "test_token";
        let expected = "/var/www/html/.well-known/acme-challenge/test_token";
        assert_eq!(challenge.get_challenge_path(token), expected);
    }

    #[test]
    fn test_challenge_url() {
        let domain = "example.com";
        let token = "test_token";
        let expected = "http://example.com/.well-known/acme-challenge/test_token";
        assert_eq!(HttpChallenge::get_challenge_url(domain, token), expected);
    }
}