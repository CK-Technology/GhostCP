// Modern mail server integration with SMTP2Go relay
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailConfig {
    pub mail_server: MailServerType,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub smtp_relay: Option<SmtpRelayConfig>,
    pub dkim_enabled: bool,
    pub dmarc_enabled: bool,
    pub spf_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailServerType {
    Stalwart,  // Modern Rust-based mail server
    Maddy,     // Lightweight Go-based mail server
    Postfix,   // Traditional (fallback)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpRelayConfig {
    pub provider: String,  // smtp2go, sendgrid, mailgun, etc.
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
}

impl Default for SmtpRelayConfig {
    fn default() -> Self {
        Self {
            provider: "smtp2go".to_string(),
            host: "mail.smtp2go.com".to_string(),
            port: 587,
            username: String::new(),
            password: String::new(),
            use_tls: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailDomain {
    pub id: Uuid,
    pub domain: String,
    pub dkim_selector: String,
    pub dkim_private_key: String,
    pub dkim_public_key: String,
    pub spf_record: String,
    pub dmarc_record: String,
    pub mx_records: Vec<MxRecord>,
    pub catch_all: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub priority: u16,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailAccount {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub domain: String,
    pub quota_mb: i64,
    pub aliases: Vec<String>,
    pub forward_to: Option<String>,
    pub autoresponder: Option<Autoresponder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Autoresponder {
    pub enabled: bool,
    pub subject: String,
    pub message: String,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct MailManager {
    config: MailConfig,
}

impl MailManager {
    pub fn new(config: MailConfig) -> Self {
        Self { config }
    }

    // Install Stalwart Mail Server (modern Rust alternative)
    pub async fn install_stalwart(&self) -> Result<()> {
        // Download and install Stalwart
        let output = Command::new("wget")
            .args(&[
                "-O",
                "/tmp/stalwart.tar.gz",
                "https://github.com/stalwartlabs/mail-server/releases/latest/download/stalwart-mail-linux-x86_64.tar.gz"
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to download Stalwart"));
        }

        Command::new("tar")
            .args(&["-xzf", "/tmp/stalwart.tar.gz", "-C", "/opt/"])
            .output()?;

        // Create systemd service
        let service_content = r#"[Unit]
Description=Stalwart Mail Server
After=network.target

[Service]
Type=simple
User=stalwart
Group=stalwart
ExecStart=/opt/stalwart/bin/stalwart-mail --config /etc/stalwart/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target"#;

        fs::write("/etc/systemd/system/stalwart.service", service_content).await?;
        
        Ok(())
    }

    // Configure Stalwart with SMTP2Go relay
    pub async fn configure_stalwart_relay(&self, relay: &SmtpRelayConfig) -> Result<()> {
        let config = format!(r#"
[server]
hostname = "{}"
data-dir = "{}"

[smtp]
bind = ["0.0.0.0:25", "[::]:25", "0.0.0.0:587", "[::]:587"]
greeting = "GhostCP Mail Server"

[smtp.relay]
host = "{}"
port = {}
auth.username = "{}"
auth.password = "{}"
auth.mechanism = "plain"
tls.enable = {}
tls.implicit = false

[imap]
bind = ["0.0.0.0:143", "[::]:143", "0.0.0.0:993", "[::]:993"]

[storage]
type = "rocksdb"
path = "{}/data"

[authentication]
type = "internal"

[queue]
retry = [1m, 5m, 15m, 30m, 1h, 2h]
expire = 5d
dsn = true
"#, 
            "mail.ghostcp.local",
            self.config.data_dir.display(),
            relay.host,
            relay.port,
            relay.username,
            relay.password,
            relay.use_tls,
            self.config.data_dir.display()
        );

        let config_path = self.config.config_dir.join("stalwart.toml");
        fs::write(config_path, config).await?;
        
        Ok(())
    }

    // Generate DKIM keys for a domain
    pub async fn generate_dkim_keys(&self, domain: &str) -> Result<(String, String)> {
        let selector = format!("mail{}", chrono::Utc::now().format("%Y%m"));
        
        // Generate RSA key pair
        Command::new("openssl")
            .args(&[
                "genrsa",
                "-out",
                &format!("/tmp/{}.{}.key", domain, selector),
                "2048"
            ])
            .output()?;

        // Extract public key
        let output = Command::new("openssl")
            .args(&[
                "rsa",
                "-in",
                &format!("/tmp/{}.{}.key", domain, selector),
                "-pubout",
                "-outform",
                "PEM"
            ])
            .output()?;

        let public_key = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        // Read private key
        let private_key = fs::read_to_string(format!("/tmp/{}.{}.key", domain, selector)).await?;

        Ok((private_key, public_key))
    }

    // Create mail domain with DNS records
    pub async fn create_mail_domain(&self, domain: &str) -> Result<MailDomain> {
        let (dkim_private, dkim_public) = self.generate_dkim_keys(domain).await?;
        let dkim_selector = format!("mail{}", chrono::Utc::now().format("%Y%m"));

        let mail_domain = MailDomain {
            id: Uuid::new_v4(),
            domain: domain.to_string(),
            dkim_selector: dkim_selector.clone(),
            dkim_private_key: dkim_private,
            dkim_public_key: dkim_public.clone(),
            spf_record: format!("v=spf1 mx a include:spf.smtp2go.com ~all"),
            dmarc_record: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{}", domain),
            mx_records: vec![
                MxRecord { priority: 10, hostname: format!("mail.{}", domain) },
                MxRecord { priority: 20, hostname: "mail.smtp2go.com".to_string() },
            ],
            catch_all: None,
        };

        // Configure in mail server
        match self.config.mail_server {
            MailServerType::Stalwart => {
                self.configure_stalwart_domain(&mail_domain).await?;
            },
            MailServerType::Maddy => {
                self.configure_maddy_domain(&mail_domain).await?;
            },
            MailServerType::Postfix => {
                self.configure_postfix_domain(&mail_domain).await?;
            },
        }

        Ok(mail_domain)
    }

    async fn configure_stalwart_domain(&self, domain: &MailDomain) -> Result<()> {
        // Add domain to Stalwart configuration
        let domain_config = format!(r#"
[[domains]]
name = "{}"
dkim.selector = "{}"
dkim.private-key = """
{}
"""
"#, domain.domain, domain.dkim_selector, domain.dkim_private_key);

        let config_path = self.config.config_dir.join(format!("{}.toml", domain.domain));
        fs::write(config_path, domain_config).await?;
        
        // Reload Stalwart
        Command::new("systemctl")
            .args(&["reload", "stalwart"])
            .output()?;

        Ok(())
    }

    async fn configure_maddy_domain(&self, domain: &MailDomain) -> Result<()> {
        // Maddy configuration
        let domain_config = format!(r#"
$(hostname) = {}
$(primary_domain) = {}

tls file /etc/ghostcp/ssl/{}/fullchain.pem /etc/ghostcp/ssl/{}/privkey.pem

auth.pass_table pass_table
pass_table file /etc/maddy/passwords

storage.imapsql imapsql
imapsql sqlite3 /var/lib/maddy/imapsql.db

table.domains file /etc/maddy/domains
table.aliases file /etc/maddy/aliases

smtp tcp://0.0.0.0:25 {{
    hostname $(hostname)
    tls &local_tls

    dkim {{
        domain {}
        selector {}
        key_path /etc/maddy/dkim_keys/{}.key
    }}

    deliver_to &local_routing
}}
"#, domain.domain, domain.domain, domain.domain, domain.domain,
     domain.domain, domain.dkim_selector, domain.domain);

        let config_path = self.config.config_dir.join("maddy.conf");
        fs::write(config_path, domain_config).await?;
        
        Ok(())
    }

    async fn configure_postfix_domain(&self, _domain: &MailDomain) -> Result<()> {
        // Traditional Postfix configuration (fallback)
        // Implementation for backwards compatibility
        Ok(())
    }

    // Create mail account
    pub async fn create_mail_account(
        &self,
        email: &str,
        password: &str,
        quota_mb: i64,
    ) -> Result<MailAccount> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid email address"));
        }

        let username = parts[0];
        let domain = parts[1];

        let account = MailAccount {
            id: Uuid::new_v4(),
            email: email.to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            quota_mb,
            aliases: vec![],
            forward_to: None,
            autoresponder: None,
        };

        // Create account in mail server
        match self.config.mail_server {
            MailServerType::Stalwart => {
                self.create_stalwart_account(&account, password).await?;
            },
            MailServerType::Maddy => {
                self.create_maddy_account(&account, password).await?;
            },
            MailServerType::Postfix => {
                self.create_postfix_account(&account, password).await?;
            },
        }

        Ok(account)
    }

    async fn create_stalwart_account(&self, account: &MailAccount, password: &str) -> Result<()> {
        // Use Stalwart's API to create account
        let client = reqwest::Client::new();
        
        let response = client
            .post("http://localhost:8080/api/v1/accounts")
            .json(&serde_json::json!({
                "email": account.email,
                "password": password,
                "quota": account.quota_mb * 1024 * 1024,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to create account in Stalwart"));
        }

        Ok(())
    }

    async fn create_maddy_account(&self, account: &MailAccount, password: &str) -> Result<()> {
        // Use maddyctl to create account
        let output = Command::new("maddyctl")
            .args(&[
                "creds",
                "create",
                &account.email,
                "--password",
                password,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to create account: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Set quota
        Command::new("maddyctl")
            .args(&[
                "imap-acct",
                "set-quota",
                &account.email,
                &format!("{}M", account.quota_mb),
            ])
            .output()?;

        Ok(())
    }

    async fn create_postfix_account(&self, _account: &MailAccount, _password: &str) -> Result<()> {
        // Traditional implementation
        Ok(())
    }

    // Get DNS records for mail domain
    pub fn get_dns_records(&self, domain: &MailDomain) -> Vec<DnsRecordConfig> {
        vec![
            // MX records
            DnsRecordConfig {
                record_type: "MX".to_string(),
                name: domain.domain.clone(),
                content: format!("10 mail.{}", domain.domain),
                ttl: 3600,
            },
            DnsRecordConfig {
                record_type: "MX".to_string(),
                name: domain.domain.clone(),
                content: "20 mail.smtp2go.com".to_string(),
                ttl: 3600,
            },
            // SPF record
            DnsRecordConfig {
                record_type: "TXT".to_string(),
                name: domain.domain.clone(),
                content: domain.spf_record.clone(),
                ttl: 3600,
            },
            // DKIM record
            DnsRecordConfig {
                record_type: "TXT".to_string(),
                name: format!("{}._domainkey.{}", domain.dkim_selector, domain.domain),
                content: format!("v=DKIM1; k=rsa; p={}", domain.dkim_public_key),
                ttl: 3600,
            },
            // DMARC record
            DnsRecordConfig {
                record_type: "TXT".to_string(),
                name: format!("_dmarc.{}", domain.domain),
                content: domain.dmarc_record.clone(),
                ttl: 3600,
            },
            // Mail server A record
            DnsRecordConfig {
                record_type: "A".to_string(),
                name: format!("mail.{}", domain.domain),
                content: "SERVER_IP".to_string(), // Will be replaced with actual IP
                ttl: 3600,
            },
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordConfig {
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
}