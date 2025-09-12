// ACME/Let's Encrypt integration using acme.sh
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub acme_sh_path: PathBuf,
    pub config_home: PathBuf,
    pub cert_home: PathBuf,
    pub dns_provider: Option<String>,
    pub dns_api_key: Option<String>,
    pub default_ca: String,  // letsencrypt, zerossl, buypass
    pub email: String,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            acme_sh_path: PathBuf::from("/usr/local/bin/acme.sh"),
            config_home: PathBuf::from("/etc/ghostcp/acme"),
            cert_home: PathBuf::from("/etc/ghostcp/ssl"),
            dns_provider: None,
            dns_api_key: None,
            default_ca: "letsencrypt".to_string(),
            email: "admin@localhost".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub domain: String,
    pub alt_names: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub fullchain_path: PathBuf,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub validation_method: ValidationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationMethod {
    Http01,
    Dns01,
    TlsAlpn01,
}

pub struct AcmeManager {
    config: AcmeConfig,
}

impl AcmeManager {
    pub fn new(config: AcmeConfig) -> Self {
        Self { config }
    }

    // Install acme.sh if not present
    pub async fn install_acme_sh(&self) -> Result<()> {
        if self.config.acme_sh_path.exists() {
            return Ok(());
        }

        let output = Command::new("curl")
            .args(&[
                "-s",
                "https://get.acme.sh",
                "|",
                "sh",
                "-s",
                "--",
                "--install-online",
                "--home",
                self.config.config_home.to_str().unwrap(),
                "--cert-home",
                self.config.cert_home.to_str().unwrap(),
                "--accountemail",
                &self.config.email,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to install acme.sh: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Issue a new certificate
    pub async fn issue_certificate(
        &self,
        domain: &str,
        alt_names: Vec<String>,
        validation: ValidationMethod,
        webroot: Option<PathBuf>,
    ) -> Result<Certificate> {
        let mut args = vec![
            "--issue".to_string(),
            "-d".to_string(),
            domain.to_string(),
        ];

        // Add alternative names
        for alt in &alt_names {
            args.push("-d".to_string());
            args.push(alt.clone());
        }

        // Set validation method
        match validation {
            ValidationMethod::Http01 => {
                if let Some(webroot) = webroot {
                    args.push("-w".to_string());
                    args.push(webroot.to_str().unwrap().to_string());
                } else {
                    args.push("--standalone".to_string());
                }
            },
            ValidationMethod::Dns01 => {
                if let Some(provider) = &self.config.dns_provider {
                    args.push("--dns".to_string());
                    args.push(provider.clone());
                } else {
                    return Err(anyhow!("DNS provider not configured"));
                }
            },
            ValidationMethod::TlsAlpn01 => {
                args.push("--alpn".to_string());
            },
        }

        // Set CA
        args.push("--server".to_string());
        args.push(self.get_ca_server(&self.config.default_ca));

        // Add config paths
        args.push("--config-home".to_string());
        args.push(self.config.config_home.to_str().unwrap().to_string());
        args.push("--cert-home".to_string());
        args.push(self.config.cert_home.to_str().unwrap().to_string());

        // Run acme.sh
        let output = Command::new(&self.config.acme_sh_path)
            .args(&args)
            .env("LE_WORKING_DIR", &self.config.config_home)
            .env("LE_CONFIG_HOME", &self.config.config_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to issue certificate: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Parse certificate paths
        let cert_dir = self.config.cert_home.join(domain);
        let cert = Certificate {
            id: Uuid::new_v4(),
            domain: domain.to_string(),
            alt_names,
            cert_path: cert_dir.join(format!("{}.cer", domain)),
            key_path: cert_dir.join(format!("{}.key", domain)),
            fullchain_path: cert_dir.join("fullchain.cer"),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            issuer: self.config.default_ca.clone(),
            validation_method: validation,
        };

        Ok(cert)
    }

    // Renew a certificate
    pub async fn renew_certificate(&self, domain: &str, force: bool) -> Result<()> {
        let mut args = vec![
            "--renew".to_string(),
            "-d".to_string(),
            domain.to_string(),
        ];

        if force {
            args.push("--force".to_string());
        }

        args.push("--config-home".to_string());
        args.push(self.config.config_home.to_str().unwrap().to_string());

        let output = Command::new(&self.config.acme_sh_path)
            .args(&args)
            .env("LE_WORKING_DIR", &self.config.config_home)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to renew certificate: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Renew all certificates
    pub async fn renew_all(&self) -> Result<Vec<String>> {
        let output = Command::new(&self.config.acme_sh_path)
            .args(&[
                "--cron",
                "--config-home", self.config.config_home.to_str().unwrap(),
            ])
            .env("LE_WORKING_DIR", &self.config.config_home)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to renew certificates: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Parse output for renewed domains
        let output_str = String::from_utf8_lossy(&output.stdout);
        let renewed: Vec<String> = output_str
            .lines()
            .filter(|line| line.contains("Cert success"))
            .map(|line| {
                line.split_whitespace()
                    .find(|word| word.contains("."))
                    .unwrap_or("")
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect();

        Ok(renewed)
    }

    // Install certificate to nginx
    pub async fn install_to_nginx(
        &self,
        domain: &str,
        nginx_cert_path: PathBuf,
        nginx_key_path: PathBuf,
        reload_cmd: Option<String>,
    ) -> Result<()> {
        let mut args = vec![
            "--install-cert".to_string(),
            "-d".to_string(),
            domain.to_string(),
            "--cert-file".to_string(),
            nginx_cert_path.to_str().unwrap().to_string(),
            "--key-file".to_string(),
            nginx_key_path.to_str().unwrap().to_string(),
            "--fullchain-file".to_string(),
            nginx_cert_path.with_extension("fullchain").to_str().unwrap().to_string(),
        ];

        if let Some(reload) = reload_cmd {
            args.push("--reloadcmd".to_string());
            args.push(reload);
        } else {
            args.push("--reloadcmd".to_string());
            args.push("systemctl reload nginx".to_string());
        }

        args.push("--config-home".to_string());
        args.push(self.config.config_home.to_str().unwrap().to_string());

        let output = Command::new(&self.config.acme_sh_path)
            .args(&args)
            .env("LE_WORKING_DIR", &self.config.config_home)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to install certificate: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Revoke a certificate
    pub async fn revoke_certificate(&self, domain: &str) -> Result<()> {
        let output = Command::new(&self.config.acme_sh_path)
            .args(&[
                "--revoke",
                "-d", domain,
                "--config-home", self.config.config_home.to_str().unwrap(),
            ])
            .env("LE_WORKING_DIR", &self.config.config_home)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to revoke certificate: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Remove certificate files
        let cert_dir = self.config.cert_home.join(domain);
        if cert_dir.exists() {
            fs::remove_dir_all(cert_dir).await?;
        }

        Ok(())
    }

    // List all certificates
    pub async fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let output = Command::new(&self.config.acme_sh_path)
            .args(&[
                "--list",
                "--config-home", self.config.config_home.to_str().unwrap(),
            ])
            .env("LE_WORKING_DIR", &self.config.config_home)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to list certificates: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Parse the output
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut certificates = Vec::new();

        for line in output_str.lines().skip(1) {  // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let domain = parts[0].to_string();
                let cert_dir = self.config.cert_home.join(&domain);
                
                certificates.push(Certificate {
                    id: Uuid::new_v4(),
                    domain: domain.clone(),
                    alt_names: vec![],
                    cert_path: cert_dir.join(format!("{}.cer", domain)),
                    key_path: cert_dir.join(format!("{}.key", domain)),
                    fullchain_path: cert_dir.join("fullchain.cer"),
                    issued_at: Utc::now(),  // Would need to parse from cert
                    expires_at: Utc::now() + chrono::Duration::days(90),
                    issuer: "letsencrypt".to_string(),
                    validation_method: ValidationMethod::Http01,
                });
            }
        }

        Ok(certificates)
    }

    fn get_ca_server(&self, ca: &str) -> String {
        match ca {
            "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory",
            "letsencrypt_test" => "https://acme-staging-v02.api.letsencrypt.org/directory",
            "zerossl" => "https://acme.zerossl.com/v2/DV90",
            "buypass" => "https://api.buypass.com/acme/directory",
            "buypass_test" => "https://api.test4.buypass.no/acme/directory",
            _ => "https://acme-v02.api.letsencrypt.org/directory",
        }.to_string()
    }

    // Setup DNS API credentials
    pub async fn setup_dns_provider(&self, provider: &str, credentials: &str) -> Result<()> {
        let env_file = self.config.config_home.join("account.conf");
        
        // Write DNS API credentials to account.conf
        let content = match provider {
            "cloudflare" => format!("export CF_Token=\"{}\"\n", credentials),
            "route53" => format!("export AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\n", 
                credentials.split(':').nth(0).unwrap_or(""),
                credentials.split(':').nth(1).unwrap_or("")),
            "godaddy" => format!("export GD_Key=\"{}\"\nexport GD_Secret=\"{}\"\n",
                credentials.split(':').nth(0).unwrap_or(""),
                credentials.split(':').nth(1).unwrap_or("")),
            _ => return Err(anyhow!("Unsupported DNS provider: {}", provider)),
        };

        fs::write(env_file, content).await?;
        Ok(())
    }
}