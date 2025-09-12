use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use super::TemplateContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxTemplateData {
    pub server_name: String,
    pub document_root: String,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub php_fpm_socket: Option<String>,
    pub custom_config: Option<String>,
}

impl From<&TemplateContext> for NginxTemplateData {
    fn from(context: &TemplateContext) -> Self {
        NginxTemplateData {
            server_name: context.domain.clone(),
            document_root: context.document_root.clone(),
            ssl_certificate: if context.ssl_enabled {
                Some(context.ssl_cert_path.clone())
            } else {
                None
            },
            ssl_certificate_key: if context.ssl_enabled {
                Some(context.ssl_key_path.clone())
            } else {
                None
            },
            php_fpm_socket: if context.php_enabled {
                Some(context.php_fpm_socket.clone())
            } else {
                None
            },
            custom_config: context.custom_config.clone(),
        }
    }
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