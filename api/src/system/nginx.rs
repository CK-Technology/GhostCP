// NGINX configuration management and deployment
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use crate::templates::{TemplateEngine, TemplateContext};

#[derive(Debug, Clone)]
pub struct NginxManager {
    config_dir: PathBuf,
    sites_available: PathBuf,
    sites_enabled: PathBuf,
    ssl_dir: PathBuf,
    template_engine: TemplateEngine,
}

impl NginxManager {
    pub fn new(template_engine: TemplateEngine) -> Self {
        Self {
            config_dir: PathBuf::from("/etc/nginx"),
            sites_available: PathBuf::from("/etc/nginx/sites-available"),
            sites_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
            ssl_dir: PathBuf::from("/etc/nginx/ssl"),
            template_engine,
        }
    }

    // Deploy a new site configuration
    pub async fn deploy_site(&self, context: &TemplateContext) -> Result<()> {
        // Generate the configuration
        let config = self.template_engine.render_nginx_vhost(context)?;
        
        // Validate the configuration syntax
        self.validate_config(&config).await?;
        
        // Write to sites-available
        let config_file = self.sites_available.join(format!("{}.conf", context.domain));
        fs::write(&config_file, config).await?;
        
        // Create symlink in sites-enabled
        let symlink = self.sites_enabled.join(format!("{}.conf", context.domain));
        if symlink.exists() {
            fs::remove_file(&symlink).await?;
        }
        
        #[cfg(unix)]
        std::os::unix::fs::symlink(&config_file, &symlink)?;
        
        // Create document root if it doesn't exist
        fs::create_dir_all(&context.document_root).await?;
        
        // Set proper permissions
        self.set_permissions(&context.document_root, &context.user, &context.group).await?;
        
        // Reload NGINX
        self.reload().await?;
        
        Ok(())
    }

    // Remove a site configuration
    pub async fn remove_site(&self, domain: &str) -> Result<()> {
        let config_file = self.sites_available.join(format!("{}.conf", domain));
        let symlink = self.sites_enabled.join(format!("{}.conf", domain));
        
        // Remove symlink first
        if symlink.exists() {
            fs::remove_file(&symlink).await?;
        }
        
        // Remove config file
        if config_file.exists() {
            fs::remove_file(&config_file).await?;
        }
        
        // Reload NGINX
        self.reload().await?;
        
        Ok(())
    }

    // Enable a site
    pub async fn enable_site(&self, domain: &str) -> Result<()> {
        let config_file = self.sites_available.join(format!("{}.conf", domain));
        let symlink = self.sites_enabled.join(format!("{}.conf", domain));
        
        if !config_file.exists() {
            return Err(anyhow!("Site configuration not found"));
        }
        
        if !symlink.exists() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&config_file, &symlink)?;
        }
        
        self.reload().await?;
        Ok(())
    }

    // Disable a site
    pub async fn disable_site(&self, domain: &str) -> Result<()> {
        let symlink = self.sites_enabled.join(format!("{}.conf", domain));
        
        if symlink.exists() {
            fs::remove_file(&symlink).await?;
        }
        
        self.reload().await?;
        Ok(())
    }

    // Install SSL certificate for a site
    pub async fn install_ssl_certificate(
        &self,
        domain: &str,
        cert_path: &Path,
        key_path: &Path,
        fullchain_path: Option<&Path>,
    ) -> Result<()> {
        // Create SSL directory for the domain
        let domain_ssl_dir = self.ssl_dir.join(domain);
        fs::create_dir_all(&domain_ssl_dir).await?;
        
        // Copy certificate files
        let dest_cert = domain_ssl_dir.join("cert.pem");
        let dest_key = domain_ssl_dir.join("key.pem");
        let dest_fullchain = domain_ssl_dir.join("fullchain.pem");
        
        fs::copy(cert_path, &dest_cert).await?;
        fs::copy(key_path, &dest_key).await?;
        
        if let Some(fullchain) = fullchain_path {
            fs::copy(fullchain, &dest_fullchain).await?;
        }
        
        // Set proper permissions (readable only by root/nginx)
        Command::new("chmod")
            .args(&["600", dest_key.to_str().unwrap()])
            .output()?;
        
        Command::new("chown")
            .args(&["root:nginx", domain_ssl_dir.to_str().unwrap(), "-R"])
            .output()?;
        
        // Update site configuration to use SSL
        self.enable_ssl_for_site(domain).await?;
        
        Ok(())
    }

    // Enable SSL for an existing site
    async fn enable_ssl_for_site(&self, domain: &str) -> Result<()> {
        // Read current configuration
        let config_file = self.sites_available.join(format!("{}.conf", domain));
        let config = fs::read_to_string(&config_file).await?;
        
        // Check if SSL is already enabled
        if config.contains("listen 443 ssl") {
            return Ok(());
        }
        
        // Update the template context and regenerate
        // This would normally fetch from database
        let mut context = TemplateContext::default();
        context.domain = domain.to_string();
        context.ssl_enabled = true;
        context.ssl_cert_path = format!("/etc/nginx/ssl/{}/fullchain.pem", domain);
        context.ssl_key_path = format!("/etc/nginx/ssl/{}/key.pem", domain);
        
        self.deploy_site(&context).await?;
        
        Ok(())
    }

    // Validate NGINX configuration
    async fn validate_config(&self, config: &str) -> Result<()> {
        // Write to temporary file
        let temp_file = format!("/tmp/nginx-test-{}.conf", uuid::Uuid::new_v4());
        fs::write(&temp_file, config).await?;
        
        // Test configuration
        let output = Command::new("nginx")
            .args(&["-t", "-c", &temp_file])
            .output()?;
        
        // Clean up temp file
        fs::remove_file(&temp_file).await.ok();
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Invalid NGINX configuration: {}", error));
        }
        
        Ok(())
    }

    // Test NGINX configuration
    pub async fn test_config(&self) -> Result<()> {
        let output = Command::new("nginx")
            .args(&["-t"])
            .output()?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("NGINX configuration test failed: {}", error));
        }
        
        Ok(())
    }

    // Reload NGINX
    pub async fn reload(&self) -> Result<()> {
        // First test the configuration
        self.test_config().await?;
        
        let output = Command::new("systemctl")
            .args(&["reload", "nginx"])
            .output()?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to reload NGINX"));
        }
        
        Ok(())
    }

    // Restart NGINX
    pub async fn restart(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(&["restart", "nginx"])
            .output()?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to restart NGINX"));
        }
        
        Ok(())
    }

    // Get NGINX status
    pub async fn status(&self) -> Result<NginxStatus> {
        let output = Command::new("systemctl")
            .args(&["status", "nginx", "--no-pager"])
            .output()?;
        
        let status_text = String::from_utf8_lossy(&output.stdout);
        let is_running = output.status.success();
        
        // Parse nginx -V for version
        let version_output = Command::new("nginx")
            .args(&["-v"])
            .output()?;
        
        let version = String::from_utf8_lossy(&version_output.stderr)
            .lines()
            .find(|line| line.contains("nginx version"))
            .and_then(|line| line.split('/').nth(1))
            .unwrap_or("unknown")
            .to_string();
        
        // Count sites
        let sites_available = fs::read_dir(&self.sites_available).await?
            .filter_map(|entry| entry.ok())
            .count();
        
        let sites_enabled = fs::read_dir(&self.sites_enabled).await?
            .filter_map(|entry| entry.ok())
            .count();
        
        Ok(NginxStatus {
            is_running,
            version,
            sites_available,
            sites_enabled,
            config_test_passed: self.test_config().await.is_ok(),
            uptime: self.get_uptime().await.unwrap_or_default(),
        })
    }

    async fn get_uptime(&self) -> Result<String> {
        let output = Command::new("systemctl")
            .args(&["show", "nginx", "--property=ActiveEnterTimestamp"])
            .output()?;
        
        let timestamp = String::from_utf8_lossy(&output.stdout);
        Ok(timestamp.trim().to_string())
    }

    // Set file permissions
    async fn set_permissions(&self, path: &str, user: &str, group: &str) -> Result<()> {
        Command::new("chown")
            .args(&["-R", &format!("{}:{}", user, group), path])
            .output()?;
        
        Command::new("chmod")
            .args(&["-R", "755", path])
            .output()?;
        
        Ok(())
    }

    // Get site statistics
    pub async fn get_site_stats(&self, domain: &str) -> Result<SiteStats> {
        let access_log = format!("/var/log/nginx/{}.access.log", domain);
        let error_log = format!("/var/log/nginx/{}.error.log", domain);
        
        // Parse access log for basic stats
        let access_count = Command::new("wc")
            .args(&["-l", &access_log])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        
        // Count errors
        let error_count = Command::new("grep")
            .args(&["-c", "error", &error_log])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        
        // Get log file sizes
        let access_size = fs::metadata(&access_log)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        
        let error_size = fs::metadata(&error_log)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        
        Ok(SiteStats {
            domain: domain.to_string(),
            access_count,
            error_count,
            access_log_size: access_size,
            error_log_size: error_size,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxStatus {
    pub is_running: bool,
    pub version: String,
    pub sites_available: usize,
    pub sites_enabled: usize,
    pub config_test_passed: bool,
    pub uptime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteStats {
    pub domain: String,
    pub access_count: u64,
    pub error_count: u64,
    pub access_log_size: u64,
    pub error_log_size: u64,
}