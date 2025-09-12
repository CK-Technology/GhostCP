// FTP server management (vsftpd/ProFTPD integration)
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpManager {
    server_type: FtpServerType,
    config_path: PathBuf,
    users_db_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FtpServerType {
    Vsftpd,
    ProFtpd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpUser {
    pub id: Uuid,
    pub username: String,
    pub home_directory: String,
    pub upload_enabled: bool,
    pub download_enabled: bool,
    pub quota_mb: Option<u32>,
    pub bandwidth_limit: Option<u32>, // KB/s
    pub max_connections: Option<u32>,
    pub allowed_ips: Vec<String>,
    pub ssl_enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl FtpManager {
    pub fn new(server_type: FtpServerType) -> Self {
        let (config_path, users_db_path) = match server_type {
            FtpServerType::Vsftpd => (
                PathBuf::from("/etc/vsftpd.conf"),
                PathBuf::from("/etc/vsftpd/users")
            ),
            FtpServerType::ProFtpd => (
                PathBuf::from("/etc/proftpd/proftpd.conf"),
                PathBuf::from("/etc/proftpd/users")
            ),
        };

        Self {
            server_type,
            config_path,
            users_db_path,
        }
    }

    // Install and configure FTP server
    pub async fn install_server(&self) -> Result<()> {
        match self.server_type {
            FtpServerType::Vsftpd => self.install_vsftpd().await,
            FtpServerType::ProFtpd => self.install_proftpd().await,
        }
    }

    async fn install_vsftpd(&self) -> Result<()> {
        // Install vsftpd
        Command::new("apt-get")
            .args(&["update", "&&", "apt-get", "install", "-y", "vsftpd"])
            .output()?;

        // Create secure configuration
        let config = r#"# GhostCP vsftpd Configuration
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH

# User restrictions
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# Passive mode
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000

# Virtual users
guest_enable=YES
guest_username=ftp
user_config_dir=/etc/vsftpd/users

# Logging
log_ftp_protocol=YES
xferlog_file=/var/log/vsftpd.log
"#;

        fs::write(&self.config_path, config)?;

        // Create users directory
        fs::create_dir_all("/etc/vsftpd/users")?;
        
        // Create userlist file
        fs::write("/etc/vsftpd.userlist", "")?;

        // Enable and start service
        Command::new("systemctl")
            .args(&["enable", "--now", "vsftpd"])
            .output()?;

        Ok(())
    }

    async fn install_proftpd(&self) -> Result<()> {
        // Install ProFTPD
        Command::new("apt-get")
            .args(&["update", "&&", "apt-get", "install", "-y", "proftpd-basic"])
            .output()?;

        let config = r#"# GhostCP ProFTPD Configuration
Include /etc/proftpd/modules.conf
UseReverseDNS off
IdentLookups off
ServerName "GhostCP FTP Server"
ServerType standalone
DeferWelcome off
MultilineRFC2228 on
DefaultServer on
ShowSymlinks on
TimeoutNoTransfer 600
TimeoutStalled 600
TimeoutIdle 1200
DisplayLogin welcome.msg
DisplayChdir .message true
ListOptions "-l"
DenyFilter \*.*/
DefaultRoot ~
Port 21

# User authentication
AuthUserFile /etc/proftpd/ftpd.passwd
AuthGroupFile /etc/proftpd/ftpd.group
RequireValidShell off

# SSL/TLS
LoadModule mod_tls.c
TLSEngine on
TLSLog /var/log/proftpd/tls.log
TLSProtocol SSLv23
TLSRequired on
TLSRSACertificateFile /etc/ssl/certs/proftpd.crt
TLSRSACertificateKeyFile /etc/ssl/private/proftpd.key
TLSOptions NoCertRequest EnableDiags NoSessionReuseRequired

# Passive ports
PassivePorts 49152 65534

<Directory />
  AllowOverwrite yes
</Directory>
"#;

        fs::write(&self.config_path, config)?;

        // Enable and start service
        Command::new("systemctl")
            .args(&["enable", "--now", "proftpd"])
            .output()?;

        Ok(())
    }

    // Create FTP user
    pub async fn create_user(&self, user: &FtpUser, password: &str) -> Result<()> {
        match self.server_type {
            FtpServerType::Vsftpd => self.create_vsftpd_user(user, password).await,
            FtpServerType::ProFtpd => self.create_proftpd_user(user, password).await,
        }
    }

    async fn create_vsftpd_user(&self, user: &FtpUser, password: &str) -> Result<()> {
        // Create system user (if not exists)
        let output = Command::new("useradd")
            .args(&[
                "-d", &user.home_directory,
                "-s", "/sbin/nologin",
                &user.username,
            ])
            .output();

        // Set password
        let passwd_input = format!("{}:{}", user.username, password);
        Command::new("chpasswd")
            .arg("-")
            .arg(&passwd_input)
            .output()?;

        // Create home directory
        fs::create_dir_all(&user.home_directory)?;
        
        // Set ownership
        Command::new("chown")
            .args(&[
                &format!("{}:{}", user.username, user.username),
                &user.home_directory,
            ])
            .output()?;

        // Create user config file
        let user_config_path = format!("/etc/vsftpd/users/{}", user.username);
        let mut config = format!("local_root={}\n", user.home_directory);
        
        if !user.upload_enabled {
            config.push_str("write_enable=NO\n");
        }
        
        if let Some(quota) = user.quota_mb {
            // Note: vsftpd doesn't have built-in quota support
            // You'd need to implement this with filesystem quotas
        }
        
        if let Some(bandwidth) = user.bandwidth_limit {
            config.push_str(&format!("anon_max_rate={}\n", bandwidth * 1024));
        }
        
        if user.ssl_enabled {
            config.push_str("force_local_data_ssl=YES\n");
            config.push_str("force_local_logins_ssl=YES\n");
        }

        fs::write(user_config_path, config)?;

        // Add user to userlist
        let mut userlist = fs::read_to_string("/etc/vsftpd.userlist").unwrap_or_default();
        userlist.push_str(&format!("{}\n", user.username));
        fs::write("/etc/vsftpd.userlist", userlist)?;

        // Reload vsftpd
        Command::new("systemctl")
            .args(&["reload", "vsftpd"])
            .output()?;

        Ok(())
    }

    async fn create_proftpd_user(&self, user: &FtpUser, password: &str) -> Result<()> {
        // Hash password for ProFTPD
        let output = Command::new("openssl")
            .args(&["passwd", "-1", password])
            .output()?;

        let hashed_password = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Create home directory
        fs::create_dir_all(&user.home_directory)?;

        // Add user to passwd file
        let user_entry = format!("{}:{}:1001:1001:{}:{}\n", 
            user.username, 
            hashed_password,
            user.username,
            user.home_directory
        );

        let mut passwd_content = fs::read_to_string("/etc/proftpd/ftpd.passwd").unwrap_or_default();
        passwd_content.push_str(&user_entry);
        fs::write("/etc/proftpd/ftpd.passwd", passwd_content)?;

        // Add group entry
        let group_entry = format!("{}:x:1001:\n", user.username);
        let mut group_content = fs::read_to_string("/etc/proftpd/ftpd.group").unwrap_or_default();
        group_content.push_str(&group_entry);
        fs::write("/etc/proftpd/ftpd.group", group_content)?;

        // Set ownership
        Command::new("chown")
            .args(&["-R", &user.username, &user.home_directory])
            .output()?;

        // Reload ProFTPD
        Command::new("systemctl")
            .args(&["reload", "proftpd"])
            .output()?;

        Ok(())
    }

    // Delete FTP user
    pub async fn delete_user(&self, username: &str) -> Result<()> {
        match self.server_type {
            FtpServerType::Vsftpd => {
                // Remove from userlist
                let userlist = fs::read_to_string("/etc/vsftpd.userlist").unwrap_or_default();
                let filtered: String = userlist.lines()
                    .filter(|line| *line != username)
                    .collect::<Vec<_>>()
                    .join("\n");
                fs::write("/etc/vsftpd.userlist", filtered)?;

                // Remove user config
                let user_config_path = format!("/etc/vsftpd/users/{}", username);
                if PathBuf::from(&user_config_path).exists() {
                    fs::remove_file(user_config_path)?;
                }

                // Remove system user
                Command::new("userdel")
                    .args(&["-r", username])
                    .output()?;

                // Reload vsftpd
                Command::new("systemctl")
                    .args(&["reload", "vsftpd"])
                    .output()?;
            },
            FtpServerType::ProFtpd => {
                // Remove from passwd file
                let passwd_content = fs::read_to_string("/etc/proftpd/ftpd.passwd").unwrap_or_default();
                let filtered: String = passwd_content.lines()
                    .filter(|line| !line.starts_with(&format!("{}:", username)))
                    .collect::<Vec<_>>()
                    .join("\n");
                fs::write("/etc/proftpd/ftpd.passwd", filtered)?;

                // Remove from group file
                let group_content = fs::read_to_string("/etc/proftpd/ftpd.group").unwrap_or_default();
                let filtered: String = group_content.lines()
                    .filter(|line| !line.starts_with(&format!("{}:", username)))
                    .collect::<Vec<_>>()
                    .join("\n");
                fs::write("/etc/proftpd/ftpd.group", filtered)?;

                // Reload ProFTPD
                Command::new("systemctl")
                    .args(&["reload", "proftpd"])
                    .output()?;
            }
        }

        Ok(())
    }

    // List FTP users
    pub async fn list_users(&self) -> Result<Vec<String>> {
        match self.server_type {
            FtpServerType::Vsftpd => {
                let content = fs::read_to_string("/etc/vsftpd.userlist").unwrap_or_default();
                Ok(content.lines().filter(|line| !line.is_empty()).map(|s| s.to_string()).collect())
            },
            FtpServerType::ProFtpd => {
                let content = fs::read_to_string("/etc/proftpd/ftpd.passwd").unwrap_or_default();
                Ok(content.lines()
                    .map(|line| line.split(':').next().unwrap_or("").to_string())
                    .filter(|username| !username.is_empty())
                    .collect())
            }
        }
    }

    // Get server status
    pub async fn get_status(&self) -> Result<FtpStatus> {
        let service_name = match self.server_type {
            FtpServerType::Vsftpd => "vsftpd",
            FtpServerType::ProFtpd => "proftpd",
        };

        let output = Command::new("systemctl")
            .args(&["is-active", service_name])
            .output()?;

        let is_running = output.status.success();

        // Get connected users count
        let connections = self.get_active_connections().await?;

        Ok(FtpStatus {
            server_type: self.server_type.clone(),
            is_running,
            active_connections: connections,
            total_users: self.list_users().await?.len() as u32,
        })
    }

    async fn get_active_connections(&self) -> Result<u32> {
        // Check for active FTP connections
        let output = Command::new("netstat")
            .args(&["-an", "|", "grep", ":21", "|", "grep", "ESTABLISHED", "|", "wc", "-l"])
            .output()?;

        if output.status.success() {
            let count_str = String::from_utf8_lossy(&output.stdout).trim();
            Ok(count_str.parse().unwrap_or(0))
        } else {
            Ok(0)
        }
    }

    // Enable/disable user
    pub async fn set_user_status(&self, username: &str, enabled: bool) -> Result<()> {
        match self.server_type {
            FtpServerType::Vsftpd => {
                let user_config_path = format!("/etc/vsftpd/users/{}", username);
                if PathBuf::from(&user_config_path).exists() {
                    let mut config = fs::read_to_string(&user_config_path)?;
                    
                    // Remove existing enabled/disabled setting
                    config = config.lines()
                        .filter(|line| !line.starts_with("guest_enable="))
                        .collect::<Vec<_>>()
                        .join("\n");
                    
                    // Add new setting
                    config.push_str(&format!("\nguest_enable={}\n", if enabled { "YES" } else { "NO" }));
                    
                    fs::write(&user_config_path, config)?;
                }
            },
            FtpServerType::ProFtpd => {
                // ProFTPD doesn't have a simple enable/disable per user
                // You'd need to implement this by modifying the config
            }
        }

        Ok(())
    }

    // Change user password
    pub async fn change_password(&self, username: &str, new_password: &str) -> Result<()> {
        match self.server_type {
            FtpServerType::Vsftpd => {
                let passwd_input = format!("{}:{}", username, new_password);
                Command::new("chpasswd")
                    .arg("-")
                    .arg(&passwd_input)
                    .output()?;
            },
            FtpServerType::ProFtpd => {
                // Hash the new password
                let output = Command::new("openssl")
                    .args(&["passwd", "-1", new_password])
                    .output()?;

                let hashed_password = String::from_utf8_lossy(&output.stdout).trim().to_string();

                // Update passwd file
                let passwd_content = fs::read_to_string("/etc/proftpd/ftpd.passwd").unwrap_or_default();
                let updated: String = passwd_content.lines()
                    .map(|line| {
                        if line.starts_with(&format!("{}:", username)) {
                            let parts: Vec<&str> = line.split(':').collect();
                            if parts.len() >= 2 {
                                format!("{}:{}:{}", parts[0], hashed_password, parts[2..].join(":"))
                            } else {
                                line.to_string()
                            }
                        } else {
                            line.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                fs::write("/etc/proftpd/ftpd.passwd", updated)?;
            }
        }

        // Reload service
        let service_name = match self.server_type {
            FtpServerType::Vsftpd => "vsftpd",
            FtpServerType::ProFtpd => "proftpd",
        };

        Command::new("systemctl")
            .args(&["reload", service_name])
            .output()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpStatus {
    pub server_type: FtpServerType,
    pub is_running: bool,
    pub active_connections: u32,
    pub total_users: u32,
}