use anyhow::Result;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub jwt_secret: String,
    pub admin_user: String,
    pub admin_password: String,
    
    // System paths
    pub templates_dir: String,
    pub nginx_config_dir: String,
    pub ssl_certs_dir: String,
    pub user_home_dir: String,
    
    // DNS providers
    pub cloudflare_api_token: Option<String>,
    pub powerdns_api_url: Option<String>,
    pub powerdns_api_key: Option<String>,
    
    // Mail settings
    pub mail_server_hostname: String,
    pub dkim_key_size: u32,
    
    // Backup settings
    pub default_backup_backend: String,
    pub backup_encryption_key: String,
    
    // Security
    pub password_min_length: u8,
    pub session_timeout_hours: u32,
    pub max_login_attempts: u32,
    
    // Resources
    pub default_web_template: String,
    pub default_php_version: String,
    pub nginx_worker_processes: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if it exists
        
        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://ghostcp:password@localhost/ghostcp".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()?,
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
            admin_user: env::var("ADMIN_USER")
                .unwrap_or_else(|_| "admin".to_string()),
            admin_password: env::var("ADMIN_PASSWORD")
                .unwrap_or_else(|_| "admin".to_string()),
                
            // System paths - following HestiaCP conventions but more secure
            templates_dir: env::var("TEMPLATES_DIR")
                .unwrap_or_else(|_| "/etc/ghostcp/templates".to_string()),
            nginx_config_dir: env::var("NGINX_CONFIG_DIR")
                .unwrap_or_else(|_| "/etc/nginx".to_string()),
            ssl_certs_dir: env::var("SSL_CERTS_DIR")
                .unwrap_or_else(|_| "/etc/ghostcp/ssl".to_string()),
            user_home_dir: env::var("USER_HOME_DIR")
                .unwrap_or_else(|_| "/home".to_string()),
                
            // DNS providers
            cloudflare_api_token: env::var("CLOUDFLARE_API_TOKEN").ok(),
            powerdns_api_url: env::var("POWERDNS_API_URL").ok(),
            powerdns_api_key: env::var("POWERDNS_API_KEY").ok(),
            
            // Mail settings
            mail_server_hostname: env::var("MAIL_SERVER_HOSTNAME")
                .unwrap_or_else(|_| "mail.example.com".to_string()),
            dkim_key_size: env::var("DKIM_KEY_SIZE")
                .unwrap_or_else(|_| "2048".to_string())
                .parse()?,
                
            // Backup settings
            default_backup_backend: env::var("DEFAULT_BACKUP_BACKEND")
                .unwrap_or_else(|_| "local".to_string()),
            backup_encryption_key: env::var("BACKUP_ENCRYPTION_KEY")
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
                
            // Security
            password_min_length: env::var("PASSWORD_MIN_LENGTH")
                .unwrap_or_else(|_| "8".to_string())
                .parse()?,
            session_timeout_hours: env::var("SESSION_TIMEOUT_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()?,
            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()?,
                
            // Resources
            default_web_template: env::var("DEFAULT_WEB_TEMPLATE")
                .unwrap_or_else(|_| "default".to_string()),
            default_php_version: env::var("DEFAULT_PHP_VERSION")
                .unwrap_or_else(|_| "8.3".to_string()),
            nginx_worker_processes: env::var("NGINX_WORKER_PROCESSES")
                .unwrap_or_else(|_| "auto".to_string()),
        })
    }
}