use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tera::{Context, Tera};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NginxVhostConfig {
    pub domain: String,
    pub aliases: Vec<String>,
    pub document_root: String,
    pub ip_address: String,
    pub ipv6_address: Option<String>,
    pub ssl_enabled: bool,
    pub ssl_force: bool,
    pub ssl_hsts: bool,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub php_enabled: bool,
    pub php_version: String,
    pub php_pool: String,
    pub access_log: String,
    pub error_log: String,
    pub custom_config: Option<String>,
    pub proxy_pass: Option<String>,
    pub static_cache_enabled: bool,
    pub gzip_enabled: bool,
    pub rate_limiting: Option<RateLimit>,
    pub security_headers: bool,
    pub wp_multisite: bool,
    pub wp_subdirectory: bool,
    pub basic_auth: Option<BasicAuth>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimit {
    pub requests_per_second: u32,
    pub burst: u32,
    pub zone_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BasicAuth {
    pub realm: String,
    pub auth_file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhpFpmPoolConfig {
    pub pool_name: String,
    pub user: String,
    pub group: String,
    pub listen: String,
    pub pm: String, // static, dynamic, ondemand
    pub pm_max_children: u32,
    pub pm_start_servers: u32,
    pub pm_min_spare_servers: u32,
    pub pm_max_spare_servers: u32,
    pub pm_max_requests: u32,
    pub php_admin_values: HashMap<String, String>,
    pub php_values: HashMap<String, String>,
    pub chroot: Option<String>,
    pub chdir: Option<String>,
    pub catch_workers_output: bool,
}

pub struct NginxTemplateEngine {
    tera: Tera,
    template_dir: String,
}

impl NginxTemplateEngine {
    pub fn new(template_dir: &str) -> Result<Self> {
        let mut tera = Tera::new(&format!("{}/**/*.tera", template_dir))?;

        // Add custom filters and functions
        tera.register_filter("escape_nginx", escape_nginx_value);
        tera.register_function("nginx_log_format", nginx_log_format);

        Ok(Self {
            tera,
            template_dir: template_dir.to_string(),
        })
    }

    pub fn generate_vhost(&self, config: &NginxVhostConfig) -> Result<String> {
        let mut context = Context::new();
        context.insert("config", config);
        context.insert("timestamp", &chrono::Utc::now().to_rfc3339());

        let template_name = if config.wp_multisite {
            "vhost_wordpress_multisite.tera"
        } else if config.proxy_pass.is_some() {
            "vhost_proxy.tera"
        } else {
            "vhost_standard.tera"
        };

        self.tera.render(template_name, &context)
            .map_err(|e| anyhow::anyhow!("Template rendering failed: {}", e))
    }

    pub fn generate_php_fpm_pool(&self, config: &PhpFpmPoolConfig) -> Result<String> {
        let mut context = Context::new();
        context.insert("config", config);

        self.tera.render("php_fpm_pool.tera", &context)
            .map_err(|e| anyhow::anyhow!("PHP-FPM template rendering failed: {}", e))
    }

    pub async fn test_nginx_config(&self) -> Result<()> {
        let output = tokio::process::Command::new("nginx")
            .args(["-t"])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Nginx config test failed: {}", stderr));
        }

        Ok(())
    }

    pub async fn reload_nginx(&self) -> Result<()> {
        let output = tokio::process::Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Nginx reload failed: {}", stderr));
        }

        tracing::info!("Nginx configuration reloaded successfully");
        Ok(())
    }
}

// Custom Tera filters and functions
fn escape_nginx_value(value: &tera::Value, _: &HashMap<String, tera::Value>) -> tera::Result<tera::Value> {
    if let tera::Value::String(s) = value {
        let escaped = s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        Ok(tera::Value::String(escaped))
    } else {
        Ok(value.clone())
    }
}

fn nginx_log_format(_args: &HashMap<String, tera::Value>) -> tera::Result<tera::Value> {
    let log_format = r#"'$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"'"#;
    Ok(tera::Value::String(log_format.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxTemplateData {
    pub server_name: String,
    pub document_root: String,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub php_fpm_socket: Option<String>,
    pub custom_config: Option<String>,
}

pub fn get_default_templates() -> HashMap<String, &'static str> {
    let mut templates = HashMap::new();
    
    templates.insert(
        "default".to_string(),
        include_str!("../../templates/nginx/vhost.conf.tera")
    );
    
    templates.insert(
        "wordpress".to_string(),
        include_str!("../../templates/nginx/wordpress.conf.tera")
    );
    
    templates.insert(
        "proxy".to_string(),
        include_str!("../../templates/nginx/proxy.conf.tera")
    );
    
    templates.insert(
        "static".to_string(),
        include_str!("../../templates/nginx/static.conf.tera")
    );
    
    templates
}