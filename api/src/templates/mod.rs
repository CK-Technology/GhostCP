use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tera::{Tera, Context, Value};

pub mod nginx;
pub mod php_fpm;
pub mod postfix;
pub mod dovecot;

use nginx::NginxTemplateData;

// Alias for backwards compatibility
pub type TemplateManager = TemplateEngine;

#[derive(Debug, Clone)]
pub struct TemplateEngine {
    pub tera: Tera,
    pub templates_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateContext {
    // Site/domain info
    pub domain: String,
    pub www_alias: bool,
    pub aliases: Vec<String>,
    pub document_root: String,
    pub user: String,
    pub group: String,
    
    // SSL/TLS configuration
    pub ssl_enabled: bool,
    pub ssl_force: bool,
    pub ssl_hsts: bool,
    pub ssl_cert_path: String,
    pub ssl_key_path: String,
    
    // PHP configuration
    pub php_enabled: bool,
    pub php_version: String,
    pub php_fpm_socket: String,
    
    // WordPress specific
    pub is_wordpress: bool,
    pub is_wp_multisite: bool,
    pub wp_multisite_type: Option<String>, // subdomain or subdirectory
    
    // Proxy configuration
    pub proxy_enabled: bool,
    pub proxy_pass: Option<String>,
    pub proxy_headers: HashMap<String, String>,
    
    // Security
    pub basic_auth_enabled: bool,
    pub basic_auth_file: Option<String>,
    pub rate_limiting: HashMap<String, String>,
    
    // Caching
    pub fastcgi_cache_enabled: bool,
    pub static_cache_enabled: bool,
    
    // Custom configuration
    pub custom_includes: Vec<String>,
    pub custom_config: Option<String>,
}

impl TemplateEngine {
    pub fn new<P: AsRef<Path>>(templates_dir: P) -> Result<Self> {
        let templates_dir = templates_dir.as_ref().to_path_buf();
        
        // Create templates directory if it doesn't exist
        if !templates_dir.exists() {
            fs::create_dir_all(&templates_dir)?;
        }
        
        // Initialize Tera with all template files
        let tera_pattern = templates_dir.join("**/*.tera");
        let mut tera = Tera::new(tera_pattern.to_str().unwrap_or("templates/**/*.tera"))?;
        
        // Add custom filters
        tera.register_filter("domain_hash", Self::domain_hash_filter);
        tera.register_filter("php_version_short", Self::php_version_short_filter);
        
        // Add built-in templates if they don't exist
        Self::ensure_default_templates(&templates_dir)?;
        
        Ok(TemplateEngine {
            tera,
            templates_dir,
        })
    }

    fn ensure_default_templates(templates_dir: &Path) -> Result<()> {
        let nginx_dir = templates_dir.join("nginx");
        let php_fpm_dir = templates_dir.join("php-fpm");
        fs::create_dir_all(&nginx_dir)?;
        fs::create_dir_all(&php_fpm_dir)?;

        // Create default NGINX vhost template if it doesn't exist
        let default_vhost = nginx_dir.join("vhost.conf.tera");
        if !default_vhost.exists() {
            fs::write(default_vhost, include_str!("../../templates/nginx/vhost.conf.tera"))?;
        }

        // Create WordPress template
        let wp_vhost = nginx_dir.join("wordpress.conf.tera");
        if !wp_vhost.exists() {
            fs::write(wp_vhost, include_str!("../../templates/nginx/wordpress.conf.tera"))?;
        }

        // Create proxy template
        let proxy_vhost = nginx_dir.join("proxy.conf.tera");
        if !proxy_vhost.exists() {
            fs::write(proxy_vhost, include_str!("../../templates/nginx/proxy.conf.tera"))?;
        }

        // Create static site template
        let static_vhost = nginx_dir.join("static.conf.tera");
        if !static_vhost.exists() {
            fs::write(static_vhost, include_str!("../../templates/nginx/static.conf.tera"))?;
        }

        // Create PHP-FPM pool template
        let php_pool = php_fpm_dir.join("pool.conf.tera");
        if !php_pool.exists() {
            fs::write(php_pool, include_str!("../../templates/php-fpm/pool.conf.tera"))?;
        }

        Ok(())
    }

    pub fn render_nginx_vhost(&self, context: &TemplateContext) -> Result<String> {
        let template_name = if context.is_wordpress {
            "nginx/wordpress.conf.tera"
        } else if context.proxy_enabled {
            "nginx/proxy.conf.tera"
        } else if !context.php_enabled {
            "nginx/static.conf.tera"
        } else {
            "nginx/vhost.conf.tera"
        };

        let mut tera_context = Context::new();
        tera_context.insert("site", context);
        
        // Add computed values
        tera_context.insert("all_domains", &Self::get_all_domains(context));
        tera_context.insert("ssl_configured", &(context.ssl_enabled && !context.ssl_cert_path.is_empty()));
        tera_context.insert("php_enabled_with_version", &context.php_enabled);

        self.tera.render(template_name, &tera_context)
            .map_err(|e| anyhow!("Template rendering failed: {}", e))
    }

    pub fn render_php_fpm_pool(&self, context: &TemplateContext) -> Result<String> {
        let mut tera_context = Context::new();
        tera_context.insert("site", context);
        tera_context.insert("pool_name", &format!("{}_{}", context.user, context.domain.replace(".", "_")));

        self.tera.render("php-fpm/pool.conf.tera", &tera_context)
            .map_err(|e| anyhow!("PHP-FPM template rendering failed: {}", e))
    }

    pub fn render_ssl_config(&self, context: &TemplateContext) -> Result<String> {
        if !context.ssl_enabled {
            return Ok(String::new());
        }

        let mut tera_context = Context::new();
        tera_context.insert("site", context);

        self.tera.render("nginx/ssl.conf.tera", &tera_context)
            .map_err(|e| anyhow!("SSL template rendering failed: {}", e))
    }

    fn get_all_domains(context: &TemplateContext) -> Vec<String> {
        let mut domains = vec![context.domain.clone()];
        
        if context.www_alias {
            domains.push(format!("www.{}", context.domain));
        }
        
        domains.extend(context.aliases.iter().cloned());
        domains
    }

    // Custom Tera filters
    fn domain_hash_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
        let domain = value.as_str().unwrap_or("");
        let hash = format!("{:x}", md5::compute(domain.as_bytes()));
        Ok(Value::String(hash[..8].to_string()))
    }

    fn php_version_short_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
        let version = value.as_str().unwrap_or("8.3");
        let short = version.replace(".", "");
        Ok(Value::String(short))
    }

    pub fn list_available_templates(&self) -> Vec<String> {
        self.tera.get_template_names().collect()
    }

    pub fn validate_template(&self, template_name: &str, context: &TemplateContext) -> Result<()> {
        let mut tera_context = Context::new();
        tera_context.insert("site", context);
        
        self.tera.render(template_name, &tera_context)
            .map(|_| ())
            .map_err(|e| anyhow!("Template validation failed: {}", e))
    }

    pub fn reload_templates(&mut self) -> Result<()> {
        let tera_pattern = self.templates_dir.join("**/*.tera");
        self.tera = Tera::new(tera_pattern.to_str().unwrap_or("templates/**/*.tera"))?;
        
        // Re-register filters
        self.tera.register_filter("domain_hash", Self::domain_hash_filter);
        self.tera.register_filter("php_version_short", Self::php_version_short_filter);
        
        Ok(())
    }
}

impl Default for TemplateContext {
    fn default() -> Self {
        TemplateContext {
            domain: "example.com".to_string(),
            www_alias: true,
            aliases: Vec::new(),
            document_root: "/var/www/html".to_string(),
            user: "www-data".to_string(),
            group: "www-data".to_string(),
            ssl_enabled: false,
            ssl_force: false,
            ssl_hsts: false,
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            php_enabled: true,
            php_version: "8.3".to_string(),
            php_fpm_socket: "/run/php/php8.3-fpm.sock".to_string(),
            is_wordpress: false,
            is_wp_multisite: false,
            wp_multisite_type: None,
            proxy_enabled: false,
            proxy_pass: None,
            proxy_headers: HashMap::new(),
            basic_auth_enabled: false,
            basic_auth_file: None,
            rate_limiting: HashMap::new(),
            fastcgi_cache_enabled: false,
            static_cache_enabled: true,
            custom_includes: Vec::new(),
            custom_config: None,
        }
    }
}