# GhostCP Deployment Guide

## Overview

This guide covers deploying GhostCP in various environments, from development to production, including Docker, bare metal, and cloud deployments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start (Docker)](#quick-start-docker)
- [Production Deployment](#production-deployment)
- [Bare Metal Installation](#bare-metal-installation)
- [Cloud Platform Deployments](#cloud-platform-deployments)
- [High Availability Setup](#high-availability-setup)
- [Security Hardening](#security-hardening)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

- **OS**: Ubuntu 20.04+ / Debian 11+ / RHEL 8+ / Rocky Linux 8+
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 20GB SSD
- **Network**: 1Gbps connection

### Recommended Requirements

- **OS**: Ubuntu 22.04 LTS
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 50GB+ NVMe SSD
- **Network**: 1Gbps+ connection
- **Additional**: Separate database server for production

### Software Dependencies

- **Docker** 24.0+ (for containerized deployment)
- **PostgreSQL** 15+ (primary database)
- **Redis** 7+ (caching and sessions)
- **NGINX** 1.20+ (reverse proxy)
- **SSL certificates** (Let's Encrypt recommended)

---

## Quick Start (Docker)

### Development Environment

```bash
# Clone repository
git clone https://github.com/your-org/ghostcp.git
cd ghostcp

# Copy environment file
cp .env.example .env

# Edit configuration
nano .env

# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Check status
docker-compose -f docker-compose.dev.yml ps

# View logs
docker-compose -f docker-compose.dev.yml logs -f ghostcp-api

# Access the application
curl http://localhost:8080/health
```

### Production Docker Deployment

```bash
# Production environment file
cp .env.example .env.prod

# Configure production settings
cat > .env.prod << 'EOF'
# Database
DATABASE_URL=postgresql://ghostcp:secure_password@postgres:5432/ghostcp

# Security
JWT_SECRET=your-super-secure-jwt-secret-key-here
BACKUP_ENCRYPTION_KEY=your-backup-encryption-key-here

# Admin user
ADMIN_USER=admin
ADMIN_PASSWORD=secure_admin_password

# External services
CLOUDFLARE_API_TOKEN=your_cloudflare_token
POWERDNS_API_URL=https://pdns.example.com:8081
POWERDNS_API_KEY=your_powerdns_key

# Mail settings
MAIL_SERVER_HOSTNAME=mail.yourdomain.com

# Production optimizations
RUST_LOG=info
NGINX_WORKER_PROCESSES=auto
DATABASE_MAX_CONNECTIONS=20
EOF

# Start production stack
docker-compose -f docker-compose.prod.yml up -d

# Initialize database and admin user
docker-compose -f docker-compose.prod.yml exec ghostcp-api \
  ghostcp-cli admin init --email admin@yourdomain.com

# Enable SSL
docker-compose -f docker-compose.prod.yml exec nginx \
  certbot --nginx -d yourdomain.com
```

**Production Docker Compose:**

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: ghostcp
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ghostcp
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups/postgres:/backups
    networks:
      - ghostcp_internal

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - ghostcp_internal

  ghostcp-api:
    image: ghostcp/api:latest
    restart: unless-stopped
    env_file: .env.prod
    depends_on:
      - postgres
      - redis
    volumes:
      - ./templates:/app/templates:ro
      - ./ssl_certs:/etc/ghostcp/ssl
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - ghostcp_internal
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl_certs:/etc/ssl/certs:ro
      - /var/log/nginx:/var/log/nginx
    depends_on:
      - ghostcp-api
    networks:
      - ghostcp_internal
      - default

volumes:
  postgres_data:
  redis_data:

networks:
  ghostcp_internal:
    internal: true
  default:
```

---

## Production Deployment

### System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create ghostcp user
sudo useradd -r -s /bin/false -d /opt/ghostcp ghostcp
sudo mkdir -p /opt/ghostcp
sudo chown ghostcp:ghostcp /opt/ghostcp
```

### SSL Certificate Setup

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Set up auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

### Environment Configuration

```bash
# Create production environment
sudo -u ghostcp cat > /opt/ghostcp/.env << 'EOF'
# Core settings
NODE_ENV=production
PORT=8080

# Database
DATABASE_URL=postgresql://ghostcp:secure_password@localhost:5432/ghostcp
DATABASE_MAX_CONNECTIONS=20
DATABASE_IDLE_TIMEOUT=30000

# Cache
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=secure_redis_password

# Security
JWT_SECRET=generate-a-secure-64-character-secret-key-here
BACKUP_ENCRYPTION_KEY=generate-another-secure-key-for-backups
SESSION_TIMEOUT_HOURS=24
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=60
RATE_LIMIT_MAX=1000

# Admin
ADMIN_USER=admin
ADMIN_PASSWORD=secure_admin_password_change_me

# Paths
TEMPLATES_DIR=/opt/ghostcp/templates
NGINX_CONFIG_DIR=/etc/nginx/sites-available
SSL_CERTS_DIR=/etc/letsencrypt/live
USER_HOME_DIR=/home

# DNS Providers
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
POWERDNS_API_URL=https://pdns.example.com:8081
POWERDNS_API_KEY=your_powerdns_api_key

# Mail
MAIL_SERVER_HOSTNAME=mail.yourdomain.com
DKIM_KEY_SIZE=2048

# Backup
DEFAULT_BACKUP_BACKEND=s3
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
S3_BUCKET=ghostcp-backups
S3_REGION=us-east-1

# Monitoring
RUST_LOG=info,ghostcp_api=debug
ENABLE_METRICS=true
METRICS_PORT=9090
EOF

# Secure the environment file
sudo chmod 600 /opt/ghostcp/.env
```

### Database Setup

```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Configure PostgreSQL
sudo -u postgres createuser ghostcp
sudo -u postgres createdb -O ghostcp ghostcp
sudo -u postgres psql -c "ALTER USER ghostcp PASSWORD 'secure_password';"

# Configure pg_hba.conf for local connections
sudo nano /etc/postgresql/15/main/pg_hba.conf
# Add: local   ghostcp         ghostcp                                 md5

# Restart PostgreSQL
sudo systemctl restart postgresql
sudo systemctl enable postgresql
```

### Application Deployment

```bash
# Deploy application
cd /opt/ghostcp
sudo -u ghostcp wget https://github.com/your-org/ghostcp/releases/latest/download/ghostcp-linux-x86_64.tar.gz
sudo -u ghostcp tar -xzf ghostcp-linux-x86_64.tar.gz

# Run database migrations
sudo -u ghostcp ./ghostcp-api migrate

# Install systemd service
sudo cat > /etc/systemd/system/ghostcp-api.service << 'EOF'
[Unit]
Description=GhostCP API Server
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=ghostcp
Group=ghostcp
WorkingDirectory=/opt/ghostcp
ExecStart=/opt/ghostcp/ghostcp-api
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
EnvironmentFile=/opt/ghostcp/.env

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ghostcp/data /var/log/ghostcp /tmp

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Start and enable service
sudo systemctl daemon-reload
sudo systemctl enable ghostcp-api
sudo systemctl start ghostcp-api

# Check status
sudo systemctl status ghostcp-api
```

### NGINX Configuration

```bash
# Install NGINX
sudo apt install -y nginx

# Create GhostCP site configuration
sudo cat > /etc/nginx/sites-available/ghostcp << 'EOF'
upstream ghostcp_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Logging
    access_log /var/log/nginx/ghostcp.access.log;
    error_log /var/log/nginx/ghostcp.error.log;
    
    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://ghostcp_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Authentication endpoints with stricter rate limiting
    location /api/v1/auth/ {
        limit_req zone=login burst=5 nodelay;
        
        proxy_pass http://ghostcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://ghostcp_backend;
        access_log off;
    }
    
    # Metrics endpoint (restrict access)
    location /metrics {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        
        proxy_pass http://ghostcp_backend;
    }
    
    # Static files
    location / {
        root /opt/ghostcp/public;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
    }
    
    # Security - deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ \.(env|conf|config)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/ghostcp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Bare Metal Installation

### Ubuntu 22.04 LTS Installation

```bash
#!/bin/bash
# install-ghostcp.sh - Complete bare metal installation script

set -e

echo "🚀 Installing GhostCP on Ubuntu 22.04 LTS"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root" 
   exit 1
fi

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    curl wget gnupg2 software-properties-common \
    apt-transport-https ca-certificates lsb-release \
    build-essential pkg-config libssl-dev \
    postgresql postgresql-contrib \
    redis-server nginx certbot python3-certbot-nginx \
    ufw fail2ban logrotate

# Create ghostcp user
sudo useradd -r -m -s /bin/bash -d /opt/ghostcp ghostcp
sudo mkdir -p /opt/ghostcp/{bin,data,logs,templates,backups}
sudo chown -R ghostcp:ghostcp /opt/ghostcp

# Install Rust for building from source (optional)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Configure PostgreSQL
sudo -u postgres createuser ghostcp
sudo -u postgres createdb -O ghostcp ghostcp
sudo -u postgres psql -c "ALTER USER ghostcp PASSWORD 'secure_password';"

# Configure Redis
sudo sed -i 's/# requirepass foobared/requirepass secure_redis_password/' /etc/redis/redis.conf
sudo systemctl restart redis-server
sudo systemctl enable redis-server

# Install GhostCP binary
cd /tmp
wget https://github.com/your-org/ghostcp/releases/latest/download/ghostcp-linux-x86_64.tar.gz
tar -xzf ghostcp-linux-x86_64.tar.gz
sudo cp ghostcp-api /opt/ghostcp/bin/
sudo chown ghostcp:ghostcp /opt/ghostcp/bin/ghostcp-api
sudo chmod +x /opt/ghostcp/bin/ghostcp-api

# Create environment file
sudo -u ghostcp cat > /opt/ghostcp/.env << 'EOF'
DATABASE_URL=postgresql://ghostcp:secure_password@localhost:5432/ghostcp
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=generate-your-secure-jwt-secret
ADMIN_USER=admin
ADMIN_PASSWORD=change-this-password
RUST_LOG=info
EOF

# Run initial setup
sudo -u ghostcp /opt/ghostcp/bin/ghostcp-api migrate

# Install systemd service
sudo tee /etc/systemd/system/ghostcp-api.service > /dev/null << 'EOF'
[Unit]
Description=GhostCP API Server
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=ghostcp
Group=ghostcp
WorkingDirectory=/opt/ghostcp
ExecStart=/opt/ghostcp/bin/ghostcp-api
Restart=always
RestartSec=5
EnvironmentFile=/opt/ghostcp/.env

[Install]
WantedBy=multi-user.target
EOF

# Start services
sudo systemctl daemon-reload
sudo systemctl enable ghostcp-api
sudo systemctl start ghostcp-api

# Configure firewall
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Configure fail2ban
sudo tee /etc/fail2ban/jail.d/ghostcp.conf > /dev/null << 'EOF'
[ghostcp-auth]
enabled = true
port = http,https
filter = ghostcp-auth
logpath = /var/log/nginx/ghostcp.access.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

echo "✅ GhostCP installation completed!"
echo "🔗 Access: http://$(curl -s ifconfig.me)"
echo "👤 Admin user: admin"
echo "🔑 Admin password: check /opt/ghostcp/.env"
echo ""
echo "Next steps:"
echo "1. Configure domain name and SSL certificate"
echo "2. Update admin password"
echo "3. Configure DNS providers"
echo "4. Set up monitoring"
```

---

## Cloud Platform Deployments

### AWS Deployment

**AWS Infrastructure (Terraform):**

```hcl
# main.tf
provider "aws" {
  region = var.aws_region
}

# VPC and networking
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "ghostcp-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = true
  
  tags = {
    Environment = var.environment
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "ghostcp" {
  identifier = "ghostcp-${var.environment}"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r6g.large"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type         = "gp3"
  storage_encrypted    = true
  
  db_name  = "ghostcp"
  username = "ghostcp"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.ghostcp.name
  
  backup_window      = "03:00-04:00"
  backup_retention_period = 30
  maintenance_window = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "ghostcp-${var.environment}-final-snapshot"
  
  tags = {
    Name = "GhostCP Database"
    Environment = var.environment
  }
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "ghostcp" {
  name       = "ghostcp-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "ghostcp" {
  replication_group_id       = "ghostcp-${var.environment}"
  description                = "GhostCP Redis cluster"
  
  node_type           = "cache.r6g.large"
  port                = 6379
  parameter_group_name = "default.redis7"
  
  num_cache_clusters = 2
  
  subnet_group_name  = aws_elasticache_subnet_group.ghostcp.name
  security_group_ids = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_password
  
  tags = {
    Name = "GhostCP Redis"
    Environment = var.environment
  }
}

# Application Load Balancer
resource "aws_lb" "ghostcp" {
  name               = "ghostcp-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
  
  enable_deletion_protection = var.environment == "production"
  
  tags = {
    Name = "GhostCP ALB"
    Environment = var.environment
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "ghostcp" {
  name = "ghostcp-${var.environment}"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = {
    Name = "GhostCP Cluster"
    Environment = var.environment
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "ghostcp_api" {
  family                   = "ghostcp-api"
  network_mode            = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                     = 1024
  memory                  = 2048
  execution_role_arn      = aws_iam_role.ecs_execution_role.arn
  task_role_arn          = aws_iam_role.ecs_task_role.arn
  
  container_definitions = jsonencode([
    {
      name  = "ghostcp-api"
      image = "ghostcp/api:${var.app_version}"
      
      environment = [
        {
          name  = "DATABASE_URL"
          value = "postgresql://ghostcp:${var.db_password}@${aws_db_instance.ghostcp.endpoint}:5432/ghostcp"
        },
        {
          name  = "REDIS_URL"
          value = "redis://${aws_elasticache_replication_group.ghostcp.configuration_endpoint_address}:6379"
        }
      ]
      
      secrets = [
        {
          name      = "JWT_SECRET"
          valueFrom = aws_ssm_parameter.jwt_secret.arn
        }
      ]
      
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      
      healthCheck = {
        command = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval = 30
        timeout = 5
        retries = 3
        startPeriod = 60
      }
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ghostcp_api.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
  
  tags = {
    Name = "GhostCP API Task Definition"
    Environment = var.environment
  }
}
```

**ECS Service Configuration:**

```hcl
# ECS Service
resource "aws_ecs_service" "ghostcp_api" {
  name            = "ghostcp-api"
  cluster         = aws_ecs_cluster.ghostcp.id
  task_definition = aws_ecs_task_definition.ghostcp_api.arn
  desired_count   = var.environment == "production" ? 3 : 1
  launch_type     = "FARGATE"
  
  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.ghostcp_api.arn
    container_name   = "ghostcp-api"
    container_port   = 8080
  }
  
  depends_on = [aws_lb_listener.ghostcp]
  
  tags = {
    Name = "GhostCP API Service"
    Environment = var.environment
  }
}

# Auto Scaling
resource "aws_appautoscaling_target" "ghostcp_api" {
  max_capacity       = 10
  min_capacity       = var.environment == "production" ? 3 : 1
  resource_id        = "service/${aws_ecs_cluster.ghostcp.name}/${aws_ecs_service.ghostcp_api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ghostcp_api_cpu" {
  name               = "ghostcp-api-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ghostcp_api.resource_id
  scalable_dimension = aws_appautoscaling_target.ghostcp_api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ghostcp_api.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}
```

### Google Cloud Platform Deployment

**GKE Deployment:**

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ghostcp
  
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ghostcp-config
  namespace: ghostcp
data:
  RUST_LOG: "info"
  TEMPLATES_DIR: "/app/templates"
  NGINX_CONFIG_DIR: "/etc/nginx"
  
---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghostcp-secrets
  namespace: ghostcp
type: Opaque
stringData:
  DATABASE_URL: "postgresql://ghostcp:password@postgres:5432/ghostcp"
  REDIS_URL: "redis://redis:6379/0"
  JWT_SECRET: "your-jwt-secret"
  CLOUDFLARE_API_TOKEN: "your-cloudflare-token"
  
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghostcp-api
  namespace: ghostcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ghostcp-api
  template:
    metadata:
      labels:
        app: ghostcp-api
    spec:
      containers:
      - name: ghostcp-api
        image: gcr.io/your-project/ghostcp-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        envFrom:
        - configMapRef:
            name: ghostcp-config
        - secretRef:
            name: ghostcp-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
            
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: ghostcp-api-service
  namespace: ghostcp
spec:
  selector:
    app: ghostcp-api
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
  
---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ghostcp-ingress
  namespace: ghostcp
  annotations:
    kubernetes.io/ingress.class: "gce"
    kubernetes.io/ingress.global-static-ip-name: "ghostcp-ip"
    networking.gke.io/managed-certificates: "ghostcp-ssl-cert"
spec:
  rules:
  - host: ghostcp.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ghostcp-api-service
            port:
              number: 80
```

### Azure Deployment

**Azure Container Instances:**

```yaml
# azure-container-group.yaml
apiVersion: 2019-12-01
location: eastus
name: ghostcp-container-group
properties:
  containers:
  - name: ghostcp-api
    properties:
      image: ghostcp/api:latest
      resources:
        requests:
          cpu: 2
          memoryInGb: 4
      ports:
      - port: 8080
        protocol: TCP
      environmentVariables:
      - name: DATABASE_URL
        secureValue: postgresql://ghostcp:password@postgres.database.azure.com:5432/ghostcp
      - name: REDIS_URL
        value: redis://ghostcp-redis.redis.cache.windows.net:6380
      - name: JWT_SECRET
        secureValue: your-jwt-secret
  - name: nginx
    properties:
      image: nginx:alpine
      resources:
        requests:
          cpu: 0.5
          memoryInGb: 0.5
      ports:
      - port: 80
        protocol: TCP
      - port: 443
        protocol: TCP
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
    dnsNameLabel: ghostcp-demo
tags:
  Environment: production
  Application: ghostcp
```

---

## High Availability Setup

### Multi-Node Configuration

```yaml
# docker-compose.ha.yml
version: '3.8'

services:
  # Load Balancer
  haproxy:
    image: haproxy:alpine
    ports:
      - "80:80"
      - "443:443"
      - "8404:8404"  # Stats
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
      - ./ssl:/etc/ssl/certs:ro
    networks:
      - ghostcp_frontend
    depends_on:
      - ghostcp-api-1
      - ghostcp-api-2
      - ghostcp-api-3

  # API Instances
  ghostcp-api-1:
    image: ghostcp/api:latest
    hostname: ghostcp-api-1
    env_file: .env.prod
    environment:
      - NODE_ID=1
    volumes:
      - ./templates:/app/templates:ro
    networks:
      - ghostcp_frontend
      - ghostcp_backend
    depends_on:
      - postgres-primary
      - redis-cluster

  ghostcp-api-2:
    image: ghostcp/api:latest
    hostname: ghostcp-api-2
    env_file: .env.prod
    environment:
      - NODE_ID=2
    volumes:
      - ./templates:/app/templates:ro
    networks:
      - ghostcp_frontend
      - ghostcp_backend

  ghostcp-api-3:
    image: ghostcp/api:latest
    hostname: ghostcp-api-3
    env_file: .env.prod
    environment:
      - NODE_ID=3
    volumes:
      - ./templates:/app/templates:ro
    networks:
      - ghostcp_frontend
      - ghostcp_backend

  # Database Cluster
  postgres-primary:
    image: postgres:16
    environment:
      POSTGRES_DB: ghostcp
      POSTGRES_USER: ghostcp
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: ${REPLICATION_PASSWORD}
    volumes:
      - postgres_primary_data:/var/lib/postgresql/data
      - ./postgres-primary.conf:/etc/postgresql/postgresql.conf:ro
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    networks:
      - ghostcp_backend

  postgres-replica-1:
    image: postgres:16
    environment:
      PGUSER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_PRIMARY_USER: replicator
      POSTGRES_PRIMARY_PASSWORD: ${REPLICATION_PASSWORD}
      POSTGRES_MASTER_SERVICE: postgres-primary
    volumes:
      - postgres_replica1_data:/var/lib/postgresql/data
    networks:
      - ghostcp_backend
    depends_on:
      - postgres-primary

  # Redis Cluster
  redis-1:
    image: redis:7-alpine
    command: redis-server /etc/redis/redis.conf
    volumes:
      - ./redis-cluster.conf:/etc/redis/redis.conf:ro
      - redis1_data:/data
    networks:
      - ghostcp_backend

  redis-2:
    image: redis:7-alpine
    command: redis-server /etc/redis/redis.conf
    volumes:
      - ./redis-cluster.conf:/etc/redis/redis.conf:ro
      - redis2_data:/data
    networks:
      - ghostcp_backend

  redis-3:
    image: redis:7-alpine
    command: redis-server /etc/redis/redis.conf
    volumes:
      - ./redis-cluster.conf:/etc/redis/redis.conf:ro
      - redis3_data:/data
    networks:
      - ghostcp_backend

volumes:
  postgres_primary_data:
  postgres_replica1_data:
  redis1_data:
  redis2_data:
  redis3_data:

networks:
  ghostcp_frontend:
  ghostcp_backend:
    internal: true
```

**HAProxy Configuration:**

```
# haproxy.cfg
global
    daemon
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend ghostcp_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-XSS-Protection "1; mode=block"
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 50 }
    
    default_backend ghostcp_api_servers

backend ghostcp_api_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    
    server api-1 ghostcp-api-1:8080 check inter 5s
    server api-2 ghostcp-api-2:8080 check inter 5s
    server api-3 ghostcp-api-3:8080 check inter 5s

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

---

## Security Hardening

### System Security

```bash
#!/bin/bash
# security-hardening.sh

# Disable root SSH access
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Configure automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Install and configure fail2ban
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.d/ghostcp.conf > /dev/null << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5

[nginx-req-limit]
enabled = true
filter = nginx-req-limit
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

# Configure UFW firewall
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Secure shared memory
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab

# Disable unnecessary services
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
sudo systemctl disable bluetooth

# Set up log monitoring
sudo tee /etc/logrotate.d/ghostcp > /dev/null << 'EOF'
/var/log/ghostcp/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 ghostcp ghostcp
    postrotate
        systemctl reload ghostcp-api > /dev/null 2>&1 || true
    endscript
}
EOF
```

### Application Security

```rust
// Security middleware configuration
use tower_http::cors::{Any, CorsLayer};
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub fn create_security_layers() -> (impl Layer<Router>, impl Layer<Router>) {
    let cors = CorsLayer::new()
        .allow_origin("https://yourdomain.com".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        .max_age(Duration::from_secs(86400));

    let security_headers = |request: Request, next: Next| async move {
        let mut response = next.run(request).await;
        
        let headers = response.headers_mut();
        headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
        headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
        headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
        headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
        headers.insert("Content-Security-Policy", HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        ));
        
        response
    };

    let rate_limit = tower::ServiceBuilder::new()
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(cors);

    (rate_limit, axum::middleware::from_fn(security_headers))
}
```

---

## Monitoring & Maintenance

### Monitoring Setup

```yaml
# monitoring/docker-compose.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

  alertmanager:
    image: prom/alertmanager:latest
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro

volumes:
  prometheus_data:
  grafana_data:
```

**Prometheus Configuration:**

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert.rules"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'ghostcp-api'
    static_configs:
      - targets: ['ghostcp-api-1:9090', 'ghostcp-api-2:9090', 'ghostcp-api-3:9090']
    scrape_interval: 5s
    metrics_path: /metrics

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres_exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis_exporter:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx_exporter:9113']
```

### Backup Strategy

```bash
#!/bin/bash
# backup-script.sh

set -e

BACKUP_DIR="/opt/ghostcp/backups"
RETENTION_DAYS=30
S3_BUCKET="ghostcp-backups"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
pg_dump ghostcp | gzip > "$BACKUP_DIR/ghostcp-db-$(date +%Y%m%d-%H%M%S).sql.gz"

# Configuration backup
tar -czf "$BACKUP_DIR/ghostcp-config-$(date +%Y%m%d-%H%M%S).tar.gz" \
  /opt/ghostcp/.env \
  /opt/ghostcp/templates \
  /etc/nginx/sites-available/ghostcp \
  /etc/systemd/system/ghostcp-api.service

# Upload to S3
aws s3 sync "$BACKUP_DIR" "s3://$S3_BUCKET/$(hostname)/" --delete

# Clean old local backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Verify backup integrity
for backup in "$BACKUP_DIR"/*.sql.gz; do
  if ! gzip -t "$backup"; then
    echo "ERROR: Backup $backup is corrupted!"
    exit 1
  fi
done

echo "Backup completed successfully at $(date)"
```

### Health Monitoring

```bash
#!/bin/bash
# health-check.sh

API_URL="http://localhost:8080"
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Check API health
if ! curl -f "$API_URL/health" > /dev/null 2>&1; then
  echo "API health check failed"
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"🚨 GhostCP API is down!"}' \
    "$SLACK_WEBHOOK"
  exit 1
fi

# Check database connection
if ! pg_isready -h localhost -U ghostcp > /dev/null 2>&1; then
  echo "Database connection failed"
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"🚨 GhostCP Database is unreachable!"}' \
    "$SLACK_WEBHOOK"
  exit 1
fi

# Check Redis connection
if ! redis-cli ping > /dev/null 2>&1; then
  echo "Redis connection failed"
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"⚠️ GhostCP Redis is unreachable!"}' \
    "$SLACK_WEBHOOK"
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠️ GhostCP server disk usage is at ${DISK_USAGE}%\"}" \
    "$SLACK_WEBHOOK"
fi

echo "Health check passed"
```

---

## Troubleshooting

### Common Issues

**API Won't Start:**
```bash
# Check logs
journalctl -u ghostcp-api -f

# Check configuration
ghostcp-api --check-config

# Test database connection
pg_isready -h localhost -U ghostcp

# Check port availability
netstat -tlnp | grep 8080
```

**Database Connection Issues:**
```bash
# Test connection
psql -h localhost -U ghostcp -d ghostcp -c "SELECT version();"

# Check PostgreSQL status
systemctl status postgresql

# Review PostgreSQL logs
tail -f /var/log/postgresql/postgresql-15-main.log
```

**SSL Certificate Issues:**
```bash
# Check certificate expiry
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/cert.pem -text -noout | grep "Not After"

# Test certificate chain
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Renew certificate
certbot renew --dry-run
```

**Performance Issues:**
```bash
# Check system resources
top
htop
iostat -x 1

# Check database performance
psql -U ghostcp -c "SELECT * FROM pg_stat_activity;"

# Check API metrics
curl http://localhost:8080/metrics
```

### Log Analysis

```bash
# API logs
tail -f /var/log/ghostcp/api.log

# NGINX access logs
tail -f /var/log/nginx/ghostcp.access.log | grep -E "(4[0-9]{2}|5[0-9]{2})"

# System logs
journalctl -u ghostcp-api --since "1 hour ago"

# Database logs
tail -f /var/log/postgresql/postgresql-15-main.log
```

### Recovery Procedures

**Database Recovery:**
```bash
# Stop application
systemctl stop ghostcp-api

# Restore database
gunzip -c /opt/ghostcp/backups/ghostcp-db-20241201-120000.sql.gz | psql -U ghostcp ghostcp

# Run migrations
ghostcp-api migrate

# Start application
systemctl start ghostcp-api
```

**Configuration Recovery:**
```bash
# Restore configuration
tar -xzf /opt/ghostcp/backups/ghostcp-config-20241201-120000.tar.gz -C /

# Reload services
systemctl daemon-reload
systemctl reload nginx
systemctl restart ghostcp-api
```

This deployment guide provides comprehensive instructions for setting up GhostCP in various environments with proper security, monitoring, and maintenance procedures.