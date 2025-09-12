// 1-click application deployment system for WordPress, Ghost, and containerized apps
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::templates::TemplateManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDeploymentManager {
    pub templates_path: PathBuf,
    pub apps_path: PathBuf,
    pub docker_enabled: bool,
    pub available_templates: Vec<AppTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: String,
    pub deployment_type: DeploymentType,
    pub requirements: AppRequirements,
    pub configuration: AppConfiguration,
    pub post_install_steps: Vec<PostInstallStep>,
    pub logo_url: Option<String>,
    pub documentation_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentType {
    PHP {
        php_version: String,
        extensions: Vec<String>,
    },
    Docker {
        image: String,
        tag: String,
        compose_file: Option<String>,
    },
    Static {
        build_command: Option<String>,
    },
    NodeJS {
        node_version: String,
        build_command: String,
        start_command: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRequirements {
    pub min_php_version: Option<String>,
    pub required_extensions: Vec<String>,
    pub min_memory: u64,
    pub min_disk_space: u64,
    pub database_required: Option<DatabaseType>,
    pub ssl_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MariaDB,
    SQLite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfiguration {
    pub environment_variables: HashMap<String, ConfigValue>,
    pub config_files: Vec<ConfigFile>,
    pub nginx_config: Option<String>,
    pub php_pool_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigValue {
    Static(String),
    Generated(GeneratedValue),
    UserInput {
        prompt: String,
        default: Option<String>,
        required: bool,
        field_type: InputType,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeneratedValue {
    RandomPassword(u32),
    DatabaseUrl,
    SiteUrl,
    AdminEmail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputType {
    Text,
    Password,
    Email,
    Url,
    Number,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub template: String,
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostInstallStep {
    pub name: String,
    pub command: String,
    pub working_directory: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRequest {
    pub template_id: String,
    pub domain: String,
    pub subdomain: Option<String>,
    pub user_inputs: HashMap<String, String>,
    pub database_config: Option<DatabaseConfig>,
    pub ssl_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub database_type: DatabaseType,
    pub database_name: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub id: Uuid,
    pub status: DeploymentStatus,
    pub site_url: String,
    pub admin_url: Option<String>,
    pub admin_credentials: Option<AdminCredentials>,
    pub database_info: Option<DatabaseInfo>,
    pub logs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
}

impl AppDeploymentManager {
    pub fn new(templates_path: PathBuf, apps_path: PathBuf, docker_enabled: bool) -> Self {
        let mut manager = Self {
            templates_path,
            apps_path,
            docker_enabled,
            available_templates: Vec::new(),
        };
        
        // Load built-in templates
        manager.load_builtin_templates();
        manager
    }

    fn load_builtin_templates(&mut self) {
        // WordPress Template
        self.available_templates.push(AppTemplate {
            id: "wordpress".to_string(),
            name: "WordPress".to_string(),
            description: "The world's most popular CMS".to_string(),
            version: "6.4".to_string(),
            category: "CMS".to_string(),
            deployment_type: DeploymentType::PHP {
                php_version: "8.1".to_string(),
                extensions: vec!["mysqli".to_string(), "gd".to_string(), "xml".to_string(), "zip".to_string()],
            },
            requirements: AppRequirements {
                min_php_version: Some("7.4".to_string()),
                required_extensions: vec!["mysqli".to_string(), "gd".to_string()],
                min_memory: 512 * 1024 * 1024, // 512MB
                min_disk_space: 1024 * 1024 * 1024, // 1GB
                database_required: Some(DatabaseType::MySQL),
                ssl_required: false,
            },
            configuration: AppConfiguration {
                environment_variables: HashMap::new(),
                config_files: vec![
                    ConfigFile {
                        path: "wp-config.php".to_string(),
                        template: "wordpress/wp-config.php.tpl".to_string(),
                        variables: HashMap::new(),
                    }
                ],
                nginx_config: Some("wordpress/nginx.conf.tpl".to_string()),
                php_pool_config: Some("wordpress/php-pool.conf.tpl".to_string()),
            },
            post_install_steps: vec![
                PostInstallStep {
                    name: "Set permissions".to_string(),
                    command: "chown -R www-data:www-data . && chmod -R 755 .".to_string(),
                    working_directory: None,
                    required: true,
                },
                PostInstallStep {
                    name: "Install WordPress".to_string(),
                    command: "wp core install --url={{SITE_URL}} --title='{{SITE_TITLE}}' --admin_user={{ADMIN_USER}} --admin_password={{ADMIN_PASSWORD}} --admin_email={{ADMIN_EMAIL}}".to_string(),
                    working_directory: None,
                    required: true,
                },
            ],
            logo_url: Some("https://s.w.org/style/images/wp-header-logo.png".to_string()),
            documentation_url: Some("https://wordpress.org/documentation/".to_string()),
        });

        // Ghost CMS Template
        self.available_templates.push(AppTemplate {
            id: "ghost".to_string(),
            name: "Ghost CMS".to_string(),
            description: "Modern publishing platform".to_string(),
            version: "5.0".to_string(),
            category: "CMS".to_string(),
            deployment_type: DeploymentType::NodeJS {
                node_version: "18".to_string(),
                build_command: "npm install --production".to_string(),
                start_command: "npm start".to_string(),
            },
            requirements: AppRequirements {
                min_php_version: None,
                required_extensions: Vec::new(),
                min_memory: 1024 * 1024 * 1024, // 1GB
                min_disk_space: 2048 * 1024 * 1024, // 2GB
                database_required: Some(DatabaseType::MySQL),
                ssl_required: true,
            },
            configuration: AppConfiguration {
                environment_variables: HashMap::from([
                    ("NODE_ENV".to_string(), ConfigValue::Static("production".to_string())),
                    ("database__client".to_string(), ConfigValue::Static("mysql".to_string())),
                    ("database__connection__host".to_string(), ConfigValue::Generated(GeneratedValue::DatabaseUrl)),
                    ("url".to_string(), ConfigValue::Generated(GeneratedValue::SiteUrl)),
                ]),
                config_files: vec![
                    ConfigFile {
                        path: "config.production.json".to_string(),
                        template: "ghost/config.json.tpl".to_string(),
                        variables: HashMap::new(),
                    }
                ],
                nginx_config: Some("ghost/nginx.conf.tpl".to_string()),
                php_pool_config: None,
            },
            post_install_steps: vec![
                PostInstallStep {
                    name: "Create Ghost user".to_string(),
                    command: "ghost install --no-prompt --no-stack --no-setup --dir={{APP_PATH}}".to_string(),
                    working_directory: None,
                    required: true,
                },
            ],
            logo_url: Some("https://ghost.org/images/logos/ghost-logo-orb.png".to_string()),
            documentation_url: Some("https://ghost.org/docs/".to_string()),
        });

        // Hudu Documentation Template (Docker)
        if self.docker_enabled {
            self.available_templates.push(AppTemplate {
                id: "hudu".to_string(),
                name: "Hudu Documentation".to_string(),
                description: "IT Documentation platform (self-hosted)".to_string(),
                version: "latest".to_string(),
                category: "Documentation".to_string(),
                deployment_type: DeploymentType::Docker {
                    image: "hudu/hudu".to_string(),
                    tag: "latest".to_string(),
                    compose_file: Some("hudu/docker-compose.yml".to_string()),
                },
                requirements: AppRequirements {
                    min_php_version: None,
                    required_extensions: Vec::new(),
                    min_memory: 2048 * 1024 * 1024, // 2GB
                    min_disk_space: 5120 * 1024 * 1024, // 5GB
                    database_required: Some(DatabaseType::PostgreSQL),
                    ssl_required: true,
                },
                configuration: AppConfiguration {
                    environment_variables: HashMap::from([
                        ("RAILS_ENV".to_string(), ConfigValue::Static("production".to_string())),
                        ("SECRET_KEY_BASE".to_string(), ConfigValue::Generated(GeneratedValue::RandomPassword(64))),
                        ("DATABASE_URL".to_string(), ConfigValue::Generated(GeneratedValue::DatabaseUrl)),
                        ("HUDU_ADMIN_EMAIL".to_string(), ConfigValue::Generated(GeneratedValue::AdminEmail)),
                        ("HUDU_ADMIN_PASSWORD".to_string(), ConfigValue::Generated(GeneratedValue::RandomPassword(16))),
                    ]),
                    config_files: Vec::new(),
                    nginx_config: Some("hudu/nginx.conf.tpl".to_string()),
                    php_pool_config: None,
                },
                post_install_steps: vec![
                    PostInstallStep {
                        name: "Initialize database".to_string(),
                        command: "docker-compose exec hudu rails db:create db:migrate".to_string(),
                        working_directory: None,
                        required: true,
                    },
                    PostInstallStep {
                        name: "Create admin user".to_string(),
                        command: "docker-compose exec hudu rails runner 'User.create!(email: ENV[\"HUDU_ADMIN_EMAIL\"], password: ENV[\"HUDU_ADMIN_PASSWORD\"], admin: true)'".to_string(),
                        working_directory: None,
                        required: true,
                    },
                ],
                logo_url: Some("https://www.usehudu.com/images/hudu-logo.png".to_string()),
                documentation_url: Some("https://docs.usehudu.com/".to_string()),
            });
        }
    }

    // Get available templates
    pub fn get_templates(&self) -> &Vec<AppTemplate> {
        &self.available_templates
    }

    // Get template by ID
    pub fn get_template(&self, template_id: &str) -> Option<&AppTemplate> {
        self.available_templates.iter().find(|t| t.id == template_id)
    }

    // Deploy application
    pub async fn deploy_app(&self, request: DeploymentRequest) -> Result<DeploymentResult> {
        let template = self.get_template(&request.template_id)
            .ok_or_else(|| anyhow!("Template not found"))?;

        let deployment_id = Uuid::new_v4();
        let mut result = DeploymentResult {
            id: deployment_id,
            status: DeploymentStatus::InProgress,
            site_url: format!("https://{}", request.domain),
            admin_url: None,
            admin_credentials: None,
            database_info: None,
            logs: Vec::new(),
            created_at: Utc::now(),
        };

        // Create app directory
        let app_path = self.apps_path.join(&request.domain);
        fs::create_dir_all(&app_path).await?;

        // Deploy based on type
        match &template.deployment_type {
            DeploymentType::PHP { php_version, extensions } => {
                result = self.deploy_php_app(&app_path, template, &request, result).await?;
            },
            DeploymentType::Docker { image, tag, compose_file } => {
                result = self.deploy_docker_app(&app_path, template, &request, result).await?;
            },
            DeploymentType::NodeJS { node_version, build_command, start_command } => {
                result = self.deploy_nodejs_app(&app_path, template, &request, result).await?;
            },
            DeploymentType::Static { build_command } => {
                result = self.deploy_static_app(&app_path, template, &request, result).await?;
            },
        }

        // Configure web server
        self.configure_webserver(&request, template).await?;

        // Run post-install steps
        result = self.run_post_install_steps(&app_path, template, &request, result).await?;

        result.status = DeploymentStatus::Completed;
        Ok(result)
    }

    async fn deploy_php_app(
        &self,
        app_path: &PathBuf,
        template: &AppTemplate,
        request: &DeploymentRequest,
        mut result: DeploymentResult,
    ) -> Result<DeploymentResult> {
        result.logs.push("Starting PHP application deployment".to_string());

        match template.id.as_str() {
            "wordpress" => {
                // Download WordPress
                let output = Command::new("wp")
                    .args(["core", "download", "--path", app_path.to_str().unwrap()])
                    .output()?;

                if !output.status.success() {
                    result.status = DeploymentStatus::Failed("Failed to download WordPress".to_string());
                    return Ok(result);
                }

                // Create database if needed
                if let Some(db_config) = &request.database_config {
                    result.database_info = Some(DatabaseInfo {
                        host: "localhost".to_string(),
                        port: 3306,
                        database: db_config.database_name.clone(),
                        username: db_config.username.clone(),
                        password: db_config.password.clone(),
                    });
                }

                // Generate wp-config.php
                let wp_config = self.generate_wordpress_config(request).await?;
                fs::write(app_path.join("wp-config.php"), wp_config).await?;

                // Set admin credentials
                result.admin_credentials = Some(AdminCredentials {
                    username: request.user_inputs.get("admin_user").unwrap_or(&"admin".to_string()).clone(),
                    password: request.user_inputs.get("admin_password").unwrap_or(&"changeme".to_string()).clone(),
                    email: request.user_inputs.get("admin_email").unwrap_or(&"admin@example.com".to_string()).clone(),
                });

                result.admin_url = Some(format!("{}/wp-admin", result.site_url));
                result.logs.push("WordPress deployment completed".to_string());
            },
            _ => {
                return Err(anyhow!("Unknown PHP template"));
            }
        }

        Ok(result)
    }

    async fn deploy_docker_app(
        &self,
        app_path: &PathBuf,
        template: &AppTemplate,
        request: &DeploymentRequest,
        mut result: DeploymentResult,
    ) -> Result<DeploymentResult> {
        result.logs.push("Starting Docker application deployment".to_string());

        match template.id.as_str() {
            "hudu" => {
                // Generate docker-compose.yml
                let compose_content = self.generate_hudu_compose(request).await?;
                fs::write(app_path.join("docker-compose.yml"), compose_content).await?;

                // Generate environment file
                let env_content = self.generate_env_file(template, request).await?;
                fs::write(app_path.join(".env"), env_content).await?;

                // Start containers
                let output = Command::new("docker-compose")
                    .args(["up", "-d"])
                    .current_dir(app_path)
                    .output()?;

                if !output.status.success() {
                    result.status = DeploymentStatus::Failed("Failed to start Docker containers".to_string());
                    return Ok(result);
                }

                // Set admin credentials
                result.admin_credentials = Some(AdminCredentials {
                    username: "admin".to_string(),
                    password: request.user_inputs.get("admin_password").unwrap_or(&"changeme".to_string()).clone(),
                    email: request.user_inputs.get("admin_email").unwrap_or(&"admin@example.com".to_string()).clone(),
                });

                result.admin_url = Some(format!("{}/admin", result.site_url));
                result.logs.push("Hudu deployment completed".to_string());
            },
            _ => {
                return Err(anyhow!("Unknown Docker template"));
            }
        }

        Ok(result)
    }

    async fn deploy_nodejs_app(
        &self,
        app_path: &PathBuf,
        template: &AppTemplate,
        request: &DeploymentRequest,
        mut result: DeploymentResult,
    ) -> Result<DeploymentResult> {
        result.logs.push("Starting Node.js application deployment".to_string());

        match template.id.as_str() {
            "ghost" => {
                // Install Ghost CLI
                Command::new("npm")
                    .args(["install", "-g", "ghost-cli"])
                    .output()?;

                // Download and install Ghost
                let output = Command::new("ghost")
                    .args(["install", "--no-prompt", "--no-start", "--dir", app_path.to_str().unwrap()])
                    .output()?;

                if !output.status.success() {
                    result.status = DeploymentStatus::Failed("Failed to install Ghost".to_string());
                    return Ok(result);
                }

                // Generate config
                let config_content = self.generate_ghost_config(request).await?;
                fs::write(app_path.join("config.production.json"), config_content).await?;

                // Start Ghost
                Command::new("ghost")
                    .args(["start"])
                    .current_dir(app_path)
                    .output()?;

                result.admin_url = Some(format!("{}/ghost", result.site_url));
                result.logs.push("Ghost CMS deployment completed".to_string());
            },
            _ => {
                return Err(anyhow!("Unknown Node.js template"));
            }
        }

        Ok(result)
    }

    async fn deploy_static_app(
        &self,
        app_path: &PathBuf,
        template: &AppTemplate,
        request: &DeploymentRequest,
        mut result: DeploymentResult,
    ) -> Result<DeploymentResult> {
        result.logs.push("Starting static site deployment".to_string());
        // Implementation for static sites
        Ok(result)
    }

    async fn configure_webserver(&self, request: &DeploymentRequest, template: &AppTemplate) -> Result<()> {
        // Generate nginx configuration
        if let Some(nginx_template) = &template.configuration.nginx_config {
            let template_manager = TemplateManager::new(self.templates_path.clone());
            let nginx_config = template_manager.render_template(
                nginx_template,
                &self.generate_template_vars(request, template).await?,
            )?;

            let nginx_config_path = PathBuf::from("/etc/nginx/sites-available")
                .join(&request.domain);
            fs::write(&nginx_config_path, nginx_config).await?;

            // Enable site
            let sites_enabled = PathBuf::from("/etc/nginx/sites-enabled")
                .join(&request.domain);
            
            #[cfg(unix)]
            std::os::unix::fs::symlink(&nginx_config_path, &sites_enabled)?;

            // Reload nginx
            Command::new("nginx")
                .args(["-s", "reload"])
                .output()?;
        }

        Ok(())
    }

    async fn run_post_install_steps(
        &self,
        app_path: &PathBuf,
        template: &AppTemplate,
        request: &DeploymentRequest,
        mut result: DeploymentResult,
    ) -> Result<DeploymentResult> {
        for step in &template.post_install_steps {
            result.logs.push(format!("Running: {}", step.name));

            let working_dir = step.working_directory
                .as_ref()
                .map(|d| app_path.join(d))
                .unwrap_or_else(|| app_path.clone());

            // Replace template variables in command
            let command = self.replace_template_vars(&step.command, request, template).await?;

            let output = Command::new("sh")
                .args(["-c", &command])
                .current_dir(&working_dir)
                .output()?;

            if !output.status.success() && step.required {
                let error = String::from_utf8_lossy(&output.stderr);
                result.status = DeploymentStatus::Failed(format!("Failed step '{}': {}", step.name, error));
                return Ok(result);
            }

            result.logs.push(format!("Completed: {}", step.name));
        }

        Ok(result)
    }

    async fn generate_wordpress_config(&self, request: &DeploymentRequest) -> Result<String> {
        let config = format!(
            r#"<?php
define('DB_NAME', '{}');
define('DB_USER', '{}');
define('DB_PASSWORD', '{}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         '{}');
define('SECURE_AUTH_KEY',  '{}');
define('LOGGED_IN_KEY',    '{}');
define('NONCE_KEY',        '{}');
define('AUTH_SALT',        '{}');
define('SECURE_AUTH_SALT', '{}');
define('LOGGED_IN_SALT',   '{}');
define('NONCE_SALT',       '{}');

$table_prefix = 'wp_';
define('WP_DEBUG', false);

if ( ! defined( 'ABSPATH' ) ) {{
    define( 'ABSPATH', __DIR__ . '/' );
}}

require_once ABSPATH . 'wp-settings.php';
"#,
            request.database_config.as_ref().unwrap().database_name,
            request.database_config.as_ref().unwrap().username,
            request.database_config.as_ref().unwrap().password,
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
            self.generate_random_string(64),
        );

        Ok(config)
    }

    async fn generate_hudu_compose(&self, request: &DeploymentRequest) -> Result<String> {
        let compose = format!(
            r#"version: '3.8'
services:
  hudu:
    image: hudu/hudu:latest
    container_name: hudu_app
    restart: unless-stopped
    environment:
      - RAILS_ENV=production
      - SECRET_KEY_BASE={}
      - DATABASE_URL=postgresql://{}:{}@postgres:5432/{}
      - HUDU_URL={}
    volumes:
      - hudu_data:/app/uploads
      - hudu_logs:/app/log
    ports:
      - "3000:3000"
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:14
    container_name: hudu_postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB={}
      - POSTGRES_USER={}
      - POSTGRES_PASSWORD={}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    container_name: hudu_redis
    restart: unless-stopped

volumes:
  hudu_data:
  hudu_logs:
  postgres_data:

networks:
  default:
    name: hudu_network
"#,
            self.generate_random_string(64),
            request.database_config.as_ref().unwrap().username,
            request.database_config.as_ref().unwrap().password,
            request.database_config.as_ref().unwrap().database_name,
            format!("https://{}", request.domain),
            request.database_config.as_ref().unwrap().database_name,
            request.database_config.as_ref().unwrap().username,
            request.database_config.as_ref().unwrap().password,
        );

        Ok(compose)
    }

    async fn generate_ghost_config(&self, request: &DeploymentRequest) -> Result<String> {
        let config = serde_json::json!({
            "url": format!("https://{}", request.domain),
            "server": {
                "port": 2368,
                "host": "0.0.0.0"
            },
            "database": {
                "client": "mysql",
                "connection": {
                    "host": "localhost",
                    "user": request.database_config.as_ref().unwrap().username,
                    "password": request.database_config.as_ref().unwrap().password,
                    "database": request.database_config.as_ref().unwrap().database_name
                }
            },
            "mail": {
                "transport": "Direct"
            },
            "logging": {
                "transports": ["file", "stdout"]
            },
            "process": "systemd",
            "paths": {
                "contentPath": "/var/lib/ghost/content"
            }
        });

        Ok(serde_json::to_string_pretty(&config)?)
    }

    async fn generate_env_file(&self, template: &AppTemplate, request: &DeploymentRequest) -> Result<String> {
        let mut env_content = String::new();

        for (key, value) in &template.configuration.environment_variables {
            let resolved_value = match value {
                ConfigValue::Static(v) => v.clone(),
                ConfigValue::Generated(gen) => match gen {
                    GeneratedValue::RandomPassword(len) => self.generate_random_string(*len as usize),
                    GeneratedValue::DatabaseUrl => {
                        if let Some(db) = &request.database_config {
                            format!("postgresql://{}:{}@localhost:5432/{}", db.username, db.password, db.database_name)
                        } else {
                            String::new()
                        }
                    },
                    GeneratedValue::SiteUrl => format!("https://{}", request.domain),
                    GeneratedValue::AdminEmail => request.user_inputs.get("admin_email").unwrap_or(&"admin@example.com".to_string()).clone(),
                },
                ConfigValue::UserInput { prompt: _, default, required: _, field_type: _ } => {
                    request.user_inputs.get(key).unwrap_or(default.as_ref().unwrap_or(&String::new())).clone()
                },
            };

            env_content.push_str(&format!("{}={}\n", key, resolved_value));
        }

        Ok(env_content)
    }

    async fn generate_template_vars(&self, request: &DeploymentRequest, template: &AppTemplate) -> Result<HashMap<String, String>> {
        let mut vars = HashMap::new();
        vars.insert("DOMAIN".to_string(), request.domain.clone());
        vars.insert("SITE_URL".to_string(), format!("https://{}", request.domain));
        
        if let Some(db) = &request.database_config {
            vars.insert("DB_NAME".to_string(), db.database_name.clone());
            vars.insert("DB_USER".to_string(), db.username.clone());
            vars.insert("DB_PASSWORD".to_string(), db.password.clone());
        }

        for (key, value) in &request.user_inputs {
            vars.insert(key.clone(), value.clone());
        }

        Ok(vars)
    }

    async fn replace_template_vars(&self, text: &str, request: &DeploymentRequest, template: &AppTemplate) -> Result<String> {
        let vars = self.generate_template_vars(request, template).await?;
        let mut result = text.to_string();

        for (key, value) in vars {
            result = result.replace(&format!("{{{{{}}}}}", key), &value);
        }

        Ok(result)
    }

    fn generate_random_string(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}