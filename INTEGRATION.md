# GhostCP Integration Guide

## Overview

This guide covers integrating GhostCP with external systems, migrating from other control panels, and extending functionality through plugins and custom integrations.

## Table of Contents

- [Migration from Other Panels](#migration-from-other-panels)
- [DNS Provider Integration](#dns-provider-integration) 
- [ACME/SSL Certificate Integration](#acmessl-certificate-integration)
- [Backup Backend Integration](#backup-backend-integration)
- [Authentication Provider Integration](#authentication-provider-integration)
- [Monitoring & Observability](#monitoring--observability)
- [Plugin Development](#plugin-development)
- [Webhook Integration](#webhook-integration)
- [System Integration](#system-integration)

---

## Migration from Other Panels

### HestiaCP Migration

GhostCP includes built-in migration tools for HestiaCP:

```bash
# Export HestiaCP data
ghostcp-cli migrate export-hestia \
  --source-host=old.server.com \
  --source-user=admin \
  --output=/tmp/hestia-export.json

# Import to GhostCP
ghostcp-cli migrate import-hestia \
  --input=/tmp/hestia-export.json \
  --dry-run  # Preview changes first

# Actual import
ghostcp-cli migrate import-hestia \
  --input=/tmp/hestia-export.json \
  --confirm
```

**What gets migrated:**
- ✅ Users and packages
- ✅ Web domains and vhosts  
- ✅ DNS zones and records
- ✅ Mail domains and accounts
- ✅ Databases and users
- ✅ Cron jobs
- ✅ SSL certificates
- ⚠️ Files (manual rsync recommended)

### cPanel/WHM Migration

```bash
ghostcp-cli migrate export-cpanel \
  --whm-host=whm.example.com \
  --whm-user=root \
  --whm-token=TOKEN \
  --accounts=user1,user2  # or --all

ghostcp-cli migrate import-cpanel \
  --input=cpanel-export.json
```

### Plesk Migration

```bash
ghostcp-cli migrate export-plesk \
  --plesk-host=plesk.example.com \
  --plesk-user=admin \
  --plesk-pass=password

ghostcp-cli migrate import-plesk \
  --input=plesk-export.json
```

---

## DNS Provider Integration

### Cloudflare Integration

**Configuration:**
```env
# .env
CLOUDFLARE_API_TOKEN=your_cf_token_here
CLOUDFLARE_ZONE_ID=zone_id_optional
```

**API Usage:**
```bash
# Create DNS zone with Cloudflare backend
curl -X POST http://localhost:8080/api/v1/dns \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "cloudflare",
    "dnssec_enabled": true,
    "template": "cloudflare_default"
  }'
```

**Rust Integration:**
```rust
// Custom DNS provider implementation
use ghostcp::drivers::dns::{DnsProvider, DnsRecord, DnsZone};

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn create_zone(&self, zone: &DnsZone) -> Result<String, DnsError> {
        // Cloudflare API implementation
    }
    
    async fn create_record(&self, zone_id: &str, record: &DnsRecord) -> Result<String, DnsError> {
        // Record creation logic
    }
    
    async fn update_record(&self, record_id: &str, record: &DnsRecord) -> Result<(), DnsError> {
        // Update logic
    }
    
    async fn delete_record(&self, record_id: &str) -> Result<(), DnsError> {
        // Deletion logic
    }
}
```

### PowerDNS Integration

**Configuration:**
```env
POWERDNS_API_URL=http://localhost:8081/api/v1
POWERDNS_API_KEY=your_pdns_api_key
POWERDNS_DEFAULT_SOA_EDIT_API=INCEPTION-EPOCH
```

**Zone Management:**
```bash
# Create zone with PowerDNS
curl -X POST http://localhost:8080/api/v1/dns \
  -d '{
    "domain": "example.com",
    "dns_provider": "powerdns", 
    "primary_ns": "ns1.yourdns.com",
    "admin_email": "admin@example.com",
    "dnssec_enabled": true
  }'
```

### Route53 Integration

```env
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=secret...
AWS_DEFAULT_REGION=us-east-1
```

### Custom DNS Provider

```rust
// Implement custom DNS provider
pub struct CustomDnsProvider {
    api_endpoint: String,
    api_key: String,
}

#[async_trait]
impl DnsProvider for CustomDnsProvider {
    async fn create_zone(&self, zone: &DnsZone) -> Result<String, DnsError> {
        let client = reqwest::Client::new();
        let response = client
            .post(&format!("{}/zones", self.api_endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&zone)
            .send()
            .await?;
            
        let zone_data: serde_json::Value = response.json().await?;
        Ok(zone_data["id"].as_str().unwrap().to_string())
    }
    
    // Implement other required methods...
}

// Register the provider
fn register_dns_providers() -> HashMap<String, Box<dyn DnsProvider>> {
    let mut providers = HashMap::new();
    providers.insert("custom".to_string(), Box::new(CustomDnsProvider::new()));
    providers
}
```

---

## ACME/SSL Certificate Integration

### Let's Encrypt Integration

**DNS-01 Challenge with Cloudflare:**
```rust
use ghostcp::drivers::acme::{AcmeProvider, CertificateRequest};

let acme = AcmeProvider::new("letsencrypt", dns_provider).await?;
let cert_request = CertificateRequest {
    domains: vec!["example.com".to_string(), "*.example.com".to_string()],
    challenge_type: ChallengeType::Dns01,
    key_type: KeyType::Rsa2048,
};

let certificate = acme.request_certificate(cert_request).await?;
```

**HTTP-01 Challenge:**
```rust
let cert_request = CertificateRequest {
    domains: vec!["example.com".to_string()],
    challenge_type: ChallengeType::Http01,
    webroot_path: Some("/var/www/example.com/.well-known/acme-challenge".to_string()),
};
```

### ZeroSSL Integration

```env
ZEROSSL_API_KEY=your_zerossl_key
ZEROSSL_EAB_KID=eab_key_id
ZEROSSL_EAB_HMAC_KEY=eab_hmac_key
```

### BuyPass Integration

```env
BUYPASS_API_KEY=your_buypass_key
BUYPASS_DIRECTORY_URL=https://api.buypass.com/acme/directory
```

### Custom ACME Provider

```rust
pub struct CustomAcmeProvider {
    directory_url: String,
    account_key: String,
}

impl AcmeProvider for CustomAcmeProvider {
    async fn create_account(&self, email: &str) -> Result<AcmeAccount, AcmeError> {
        // Account creation logic
    }
    
    async fn request_certificate(&self, request: &CertificateRequest) -> Result<Certificate, AcmeError> {
        // Certificate request logic with challenges
    }
    
    async fn renew_certificate(&self, cert_id: &str) -> Result<Certificate, AcmeError> {
        // Renewal logic
    }
}
```

---

## Backup Backend Integration

### S3-Compatible Storage

**AWS S3:**
```env
BACKUP_BACKEND=s3
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=secret...
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=ghostcp-backups
```

**MinIO:**
```env
BACKUP_BACKEND=s3
S3_ENDPOINT=https://minio.example.com
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=backups
S3_REGION=us-east-1
```

**Wasabi:**
```env
BACKUP_BACKEND=s3
S3_ENDPOINT=https://s3.wasabisys.com
S3_ACCESS_KEY=your_wasabi_key
S3_SECRET_KEY=your_wasabi_secret
S3_BUCKET=ghostcp-backups
S3_REGION=us-east-1
```

### Restic Integration

```rust
use ghostcp::backup::ResticBackend;

let backend = ResticBackend::new(BackendConfig::S3 {
    bucket: "backups".to_string(),
    access_key: env::var("AWS_ACCESS_KEY_ID")?,
    secret_key: env::var("AWS_SECRET_ACCESS_KEY")?,
    region: "us-east-1".to_string(),
    endpoint: None,
});

let backup_job = BackupJob::new()
    .include_path("/home/user/web")
    .include_path("/var/lib/mysql")
    .exclude_pattern("*.tmp")
    .retention_policy(RetentionPolicy {
        daily: 7,
        weekly: 4,
        monthly: 6,
        yearly: 2,
    });

backend.create_backup(backup_job).await?;
```

### Custom Backup Backend

```rust
#[async_trait]
pub trait BackupBackend {
    async fn create_backup(&self, job: &BackupJob) -> Result<BackupResult, BackupError>;
    async fn restore_backup(&self, restore_job: &RestoreJob) -> Result<(), BackupError>;
    async fn list_backups(&self) -> Result<Vec<BackupInfo>, BackupError>;
    async fn delete_backup(&self, backup_id: &str) -> Result<(), BackupError>;
    async fn verify_backup(&self, backup_id: &str) -> Result<bool, BackupError>;
}

pub struct GoogleCloudBackend {
    project_id: String,
    bucket: String,
    credentials: String,
}

#[async_trait]
impl BackupBackend for GoogleCloudBackend {
    async fn create_backup(&self, job: &BackupJob) -> Result<BackupResult, BackupError> {
        // Google Cloud Storage integration
    }
    
    // Implement other methods...
}
```

---

## Authentication Provider Integration

### OIDC Integration

**Azure Entra ID:**
```env
OIDC_PROVIDER=azure
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://ghostcp.example.com/auth/callback
```

**Google Workspace:**
```env
OIDC_PROVIDER=google
GOOGLE_CLIENT_ID=your-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://ghostcp.example.com/auth/callback
GOOGLE_WORKSPACE_DOMAIN=your-company.com
```

**GitHub:**
```env
OIDC_PROVIDER=github
GITHUB_CLIENT_ID=your-github-app-id
GITHUB_CLIENT_SECRET=your-github-secret
GITHUB_ORGANIZATION=your-org  # optional
```

### LDAP/Active Directory

```env
LDAP_URL=ldap://ad.example.com:389
LDAP_BIND_DN=CN=ghostcp,OU=Service Accounts,DC=example,DC=com
LDAP_BIND_PASSWORD=service_account_password
LDAP_BASE_DN=DC=example,DC=com
LDAP_USER_FILTER=(sAMAccountName={username})
LDAP_GROUP_FILTER=(memberOf=CN=GhostCP Users,OU=Groups,DC=example,DC=com)
```

### Custom Authentication Provider

```rust
#[async_trait]
pub trait AuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult, AuthError>;
    async fn get_user_info(&self, user_id: &str) -> Result<UserInfo, AuthError>;
    async fn validate_token(&self, token: &str) -> Result<Claims, AuthError>;
}

pub struct CustomAuthProvider {
    api_endpoint: String,
    api_key: String,
}

#[async_trait] 
impl AuthProvider for CustomAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult, AuthError> {
        let client = reqwest::Client::new();
        let response = client
            .post(&format!("{}/auth/login", self.api_endpoint))
            .json(&json!({
                "username": username,
                "password": password
            }))
            .send()
            .await?;
            
        if response.status().is_success() {
            let auth_data: AuthResult = response.json().await?;
            Ok(auth_data)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}
```

---

## Monitoring & Observability

### Prometheus Integration

**Metrics Export:**
```rust
use prometheus::{Counter, Histogram, Registry, Encoder, TextEncoder};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    static ref HTTP_REQUESTS: Counter = Counter::new("http_requests_total", "Total HTTP requests")
        .expect("metric can be created");
    static ref REQUEST_DURATION: Histogram = Histogram::new("http_request_duration_seconds", "HTTP request duration")
        .expect("metric can be created");
}

// In your axum app
async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let output = encoder.encode_to_string(&metric_families).unwrap();
    
    Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(Body::from(output))
        .unwrap()
}
```

**Custom Metrics:**
```rust
// Track user operations
pub fn track_user_operation(operation: &str, user_id: &str, success: bool) {
    USER_OPERATIONS
        .with_label_values(&[operation, user_id, &success.to_string()])
        .inc();
}

// Track system resources
pub fn track_resource_usage(resource: &str, value: f64) {
    RESOURCE_USAGE
        .with_label_values(&[resource])
        .set(value);
}
```

### Grafana Dashboards

**Import dashboard configuration:**
```json
{
  "dashboard": {
    "title": "GhostCP Overview",
    "panels": [
      {
        "title": "User Operations Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ghostcp_user_operations_total[5m])",
            "legendFormat": "{{operation}}"
          }
        ]
      },
      {
        "title": "SSL Certificate Expiry",
        "type": "table",
        "targets": [
          {
            "expr": "ghostcp_ssl_certificate_expiry_days < 30",
            "format": "table"
          }
        ]
      }
    ]
  }
}
```

### Loki Log Integration

```rust
use tracing_subscriber::layer::SubscriberExt;
use tracing_loki::LokiLayer;

fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let loki_layer = LokiLayer::new(
        "http://localhost:3100",
        vec![("service".to_string(), "ghostcp-api".to_string())],
    )?;
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(loki_layer)
        .init();
        
    Ok(())
}
```

### Health Checks

```rust
#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub database: String,
    pub redis: String,
    pub dns_providers: HashMap<String, String>,
    pub backup_backends: HashMap<String, String>,
    pub version: String,
    pub uptime: u64,
}

pub async fn health_check(state: AppState) -> Json<HealthStatus> {
    let mut status = HealthStatus {
        status: "healthy".to_string(),
        database: "healthy".to_string(),
        redis: "healthy".to_string(),
        dns_providers: HashMap::new(),
        backup_backends: HashMap::new(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: get_uptime(),
    };
    
    // Check database connection
    if state.db.ping().await.is_err() {
        status.database = "unhealthy".to_string();
        status.status = "degraded".to_string();
    }
    
    // Check DNS providers
    for (name, provider) in &state.dns_providers {
        match provider.health_check().await {
            Ok(_) => status.dns_providers.insert(name.clone(), "healthy".to_string()),
            Err(_) => status.dns_providers.insert(name.clone(), "unhealthy".to_string()),
        };
    }
    
    Json(status)
}
```

---

## Plugin Development

### Plugin Architecture

```rust
#[async_trait]
pub trait GhostCpPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    
    async fn init(&mut self, config: &Config) -> Result<(), PluginError>;
    async fn on_user_created(&self, user: &User) -> Result<(), PluginError>;
    async fn on_domain_created(&self, domain: &WebDomain) -> Result<(), PluginError>;
    async fn on_ssl_issued(&self, certificate: &SslCertificate) -> Result<(), PluginError>;
    
    // Hook into web UI
    fn dashboard_widgets(&self) -> Vec<DashboardWidget>;
    fn menu_items(&self) -> Vec<MenuItem>;
}

pub struct SlackNotificationPlugin {
    webhook_url: String,
    channel: String,
}

#[async_trait]
impl GhostCpPlugin for SlackNotificationPlugin {
    fn name(&self) -> &'static str { "slack-notifications" }
    fn version(&self) -> &'static str { "1.0.0" }
    
    async fn on_user_created(&self, user: &User) -> Result<(), PluginError> {
        let message = format!("🎉 New user created: {}", user.username);
        self.send_slack_message(&message).await?;
        Ok(())
    }
    
    async fn on_ssl_issued(&self, certificate: &SslCertificate) -> Result<(), PluginError> {
        let message = format!("🔒 SSL certificate issued for: {}", certificate.domain);
        self.send_slack_message(&message).await?;
        Ok(())
    }
}
```

### Plugin Registration

```rust
// plugins/mod.rs
pub fn load_plugins() -> Vec<Box<dyn GhostCpPlugin>> {
    let mut plugins: Vec<Box<dyn GhostCpPlugin>> = vec![];
    
    // Load built-in plugins
    if env::var("SLACK_WEBHOOK_URL").is_ok() {
        plugins.push(Box::new(SlackNotificationPlugin::new()));
    }
    
    // Load external plugins from directory
    load_external_plugins(&mut plugins);
    
    plugins
}

// In main.rs
let plugins = load_plugins();
let plugin_manager = PluginManager::new(plugins);
let state = AppState {
    db,
    config,
    plugin_manager,
};
```

---

## Webhook Integration

### Webhook Configuration

```bash
# Register webhook
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://your-app.com/ghostcp-webhook",
    "events": ["user.created", "ssl.renewed", "backup.completed"],
    "secret": "webhook-secret-key",
    "active": true
  }'
```

### Webhook Handler Example (Node.js)

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const WEBHOOK_SECRET = 'webhook-secret-key';

function verifySignature(payload, signature) {
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = hmac.update(payload).digest('hex');
    return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(digest, 'hex')
    );
}

app.post('/ghostcp-webhook', (req, res) => {
    const signature = req.headers['x-ghostcp-signature'];
    const payload = JSON.stringify(req.body);
    
    if (!verifySignature(payload, signature)) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const { event, data, timestamp } = req.body;
    
    switch (event) {
        case 'user.created':
            console.log(`New user created: ${data.username}`);
            // Send welcome email, create billing account, etc.
            break;
            
        case 'ssl.renewed':
            console.log(`SSL renewed for: ${data.domain}`);
            // Update monitoring, notify customers, etc.
            break;
            
        case 'backup.completed':
            console.log(`Backup completed for user: ${data.user_id}`);
            // Update backup status, send notifications
            break;
    }
    
    res.json({ status: 'success' });
});
```

### Webhook Handler Example (Python)

```python
import hmac
import hashlib
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
WEBHOOK_SECRET = 'webhook-secret-key'

def verify_signature(payload, signature):
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)

@app.route('/ghostcp-webhook', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-GhostCP-Signature')
    payload = request.get_data(as_text=True)
    
    if not verify_signature(payload, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    data = request.json
    event = data['event']
    
    if event == 'user.created':
        user = data['data']
        send_welcome_email(user['email'])
        create_billing_account(user)
        
    elif event == 'ssl.renewed':
        cert = data['data'] 
        update_certificate_monitoring(cert['domain'])
        
    elif event == 'backup.completed':
        backup = data['data']
        update_backup_dashboard(backup['user_id'], backup['status'])
    
    return jsonify({'status': 'success'})
```

---

## System Integration

### systemd Service Integration

```ini
# /etc/systemd/system/ghostcp-api.service
[Unit]
Description=GhostCP API Server
After=network.target postgresql.service

[Service]
Type=simple
User=ghostcp
Group=ghostcp
WorkingDirectory=/opt/ghostcp
ExecStart=/opt/ghostcp/bin/ghostcp-api
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=/opt/ghostcp/.env

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ghostcp/data /var/log/ghostcp

[Install]
WantedBy=multi-user.target
```

### NGINX Reverse Proxy

```nginx
# /etc/nginx/sites-available/ghostcp
server {
    listen 80;
    server_name ghostcp.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ghostcp.example.com;
    
    ssl_certificate /etc/letsencrypt/live/ghostcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ghostcp.example.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # API backend
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for real-time features
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Static assets
    location / {
        root /opt/ghostcp/public;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

### Firewall Integration (UFW)

```bash
# Install UFW integration
ghostcp-cli firewall install-ufw

# Configure automatic rules
ghostcp-cli firewall rule add \
  --service=ssh \
  --action=allow \
  --source=192.168.1.0/24

# Block bad actors automatically
ghostcp-cli firewall enable-fail2ban
```

### Logrotate Configuration

```bash
# /etc/logrotate.d/ghostcp
/var/log/ghostcp/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 ghostcp ghostcp
    postrotate
        systemctl reload ghostcp-api
    endscript
}
```

---

## Testing Integrations

### Integration Test Example

```rust
#[tokio::test]
async fn test_cloudflare_dns_integration() {
    let dns_provider = CloudflareDns::new(
        env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN required for tests")
    ).await.unwrap();
    
    let zone = DnsZone {
        domain: "test-integration.example.com".to_string(),
        primary_ns: "ns1.ghostcp.com".to_string(),
        admin_email: "admin@example.com".to_string(),
        // ... other fields
    };
    
    // Test zone creation
    let zone_id = dns_provider.create_zone(&zone).await.unwrap();
    assert!(!zone_id.is_empty());
    
    // Test record creation
    let record = DnsRecord {
        name: "test".to_string(),
        record_type: "A".to_string(),
        value: "192.168.1.100".to_string(),
        ttl: 3600,
        // ... other fields
    };
    
    let record_id = dns_provider.create_record(&zone_id, &record).await.unwrap();
    assert!(!record_id.is_empty());
    
    // Cleanup
    dns_provider.delete_record(&record_id).await.unwrap();
    dns_provider.delete_zone(&zone_id).await.unwrap();
}
```

### End-to-End Test

```bash
#!/bin/bash
# tests/integration/e2e_test.sh

set -e

# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Wait for services
sleep 30

# Test user creation
USER_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}')

USER_ID=$(echo $USER_RESPONSE | jq -r '.id')

# Test domain creation  
DOMAIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/domains \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d "{\"domain\":\"test-$(date +%s).example.com\",\"user_id\":\"$USER_ID\"}")

# Test DNS zone creation
DNS_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/dns \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d "{\"domain\":\"test-$(date +%s).example.com\",\"user_id\":\"$USER_ID\"}")

# Test SSL certificate request
SSL_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/ssl \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d "{\"domain\":\"test-$(date +%s).example.com\",\"user_id\":\"$USER_ID\"}")

echo "✅ All integration tests passed!"

# Cleanup
docker-compose -f docker-compose.test.yml down -v
```

This integration guide covers the major aspects of extending and integrating GhostCP with external systems. Each section provides practical examples and code snippets that can be adapted to specific use cases.