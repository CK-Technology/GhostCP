#!/bin/bash

# GhostCP Setup Script
# This script sets up the GhostCP environment including SSL certificates,
# directories, and NGINX configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GHOSTCP_DIR="/etc/ghostcp"
SSL_DIR="$GHOSTCP_DIR/ssl"
TEMPLATES_DIR="$GHOSTCP_DIR/templates"
DATA_DIR="/var/lib/ghostcp"
LOG_DIR="/var/log/ghostcp"
NGINX_DIR="/etc/nginx"
HOSTNAME=$(hostname -f)

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}       GhostCP Setup Script${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p $GHOSTCP_DIR
mkdir -p $SSL_DIR
mkdir -p $TEMPLATES_DIR
mkdir -p $DATA_DIR
mkdir -p $LOG_DIR
mkdir -p $NGINX_DIR/sites-available
mkdir -p $NGINX_DIR/sites-enabled
mkdir -p /var/www/ghostcp/pkg
mkdir -p /var/www/ghostcp/assets

# Generate self-signed SSL certificate for GhostCP admin panel
echo -e "${YELLOW}Generating self-signed SSL certificate...${NC}"
if [ ! -f "$SSL_DIR/server.key" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SSL_DIR/server.key \
        -out $SSL_DIR/server.crt \
        -subj "/C=US/ST=State/L=City/O=GhostCP/CN=$HOSTNAME"
    
    chmod 600 $SSL_DIR/server.key
    chmod 644 $SSL_DIR/server.crt
    echo -e "${GREEN}SSL certificate generated${NC}"
else
    echo -e "${YELLOW}SSL certificate already exists${NC}"
fi

# Copy NGINX configuration for GhostCP admin
echo -e "${YELLOW}Setting up NGINX configuration...${NC}"
cat > $NGINX_DIR/sites-available/ghostcp-admin.conf << 'EOF'
# GhostCP Admin Panel - NGINX Configuration
upstream ghostcp_backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# HTTP redirect to HTTPS on port 2083
server {
    listen 2083;
    listen [::]:2083;
    server_name _;
    
    return 301 https://$host:2083$request_uri;
}

# HTTPS server for GhostCP Admin
server {
    listen 2083 ssl http2;
    listen [::]:2083 ssl http2;
    server_name _;
    
    ssl_certificate /etc/ghostcp/ssl/server.crt;
    ssl_certificate_key /etc/ghostcp/ssl/server.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    
    location /pkg {
        alias /var/www/ghostcp/pkg;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    location /api {
        proxy_pass http://ghostcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws {
        proxy_pass http://ghostcp_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location / {
        proxy_pass http://ghostcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    access_log /var/log/nginx/ghostcp-admin.access.log;
    error_log /var/log/nginx/ghostcp-admin.error.log;
}
EOF

# Enable the site
ln -sf $NGINX_DIR/sites-available/ghostcp-admin.conf $NGINX_DIR/sites-enabled/

# Create PostgreSQL database
echo -e "${YELLOW}Setting up PostgreSQL database...${NC}"
if command -v psql &> /dev/null; then
    sudo -u postgres psql << EOF
CREATE DATABASE IF NOT EXISTS ghostcp;
CREATE USER IF NOT EXISTS ghostcp WITH PASSWORD 'ghostcp_password';
GRANT ALL PRIVILEGES ON DATABASE ghostcp TO ghostcp;
EOF
    echo -e "${GREEN}Database configured${NC}"
else
    echo -e "${YELLOW}PostgreSQL not installed. Please install and configure manually.${NC}"
fi

# Create systemd service for GhostCP
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/ghostcp.service << EOF
[Unit]
Description=GhostCP Control Panel API
After=network.target postgresql.service

[Service]
Type=simple
User=ghostcp
Group=ghostcp
WorkingDirectory=/opt/ghostcp
Environment="DATABASE_URL=postgresql://ghostcp:ghostcp_password@localhost/ghostcp"
Environment="PORT=3000"
Environment="JWT_SECRET=$(openssl rand -hex 32)"
ExecStart=/opt/ghostcp/ghostcp-api
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create ghostcp user
if ! id -u ghostcp &>/dev/null; then
    echo -e "${YELLOW}Creating ghostcp user...${NC}"
    useradd -r -s /bin/bash -d /var/lib/ghostcp ghostcp
    usermod -aG www-data ghostcp
fi

# Set permissions
chown -R ghostcp:ghostcp $GHOSTCP_DIR
chown -R ghostcp:ghostcp $DATA_DIR
chown -R ghostcp:ghostcp $LOG_DIR
chown -R www-data:www-data /var/www/ghostcp

# Install acme.sh
echo -e "${YELLOW}Installing acme.sh...${NC}"
if [ ! -d "/root/.acme.sh" ]; then
    curl https://get.acme.sh | sh -s email=admin@$HOSTNAME
    echo -e "${GREEN}acme.sh installed${NC}"
else
    echo -e "${YELLOW}acme.sh already installed${NC}"
fi

# Create environment file
echo -e "${YELLOW}Creating environment configuration...${NC}"
cat > $GHOSTCP_DIR/.env << EOF
DATABASE_URL=postgresql://ghostcp:ghostcp_password@localhost/ghostcp
PORT=3000
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_USER=admin
ADMIN_PASSWORD=changeme

# DNS Providers (configure as needed)
#CLOUDFLARE_API_TOKEN=your_token_here
#POWERDNS_API_URL=http://localhost:8081
#POWERDNS_API_KEY=your_key_here

# Mail Settings
MAIL_SERVER_HOSTNAME=$HOSTNAME
SMTP2GO_USERNAME=
SMTP2GO_PASSWORD=

# ACME Settings
ACME_EMAIL=admin@$HOSTNAME
ACME_STAGING=false

# System Paths
TEMPLATES_DIR=$TEMPLATES_DIR
NGINX_CONFIG_DIR=$NGINX_DIR
SSL_CERTS_DIR=$SSL_DIR
DATA_DIR=$DATA_DIR
BACKUP_DIR=/var/backups/ghostcp
EOF

chmod 600 $GHOSTCP_DIR/.env

# Test NGINX configuration
echo -e "${YELLOW}Testing NGINX configuration...${NC}"
nginx -t

# Reload NGINX
echo -e "${YELLOW}Reloading NGINX...${NC}"
systemctl reload nginx

# Enable and start GhostCP service
echo -e "${YELLOW}Enabling GhostCP service...${NC}"
systemctl daemon-reload
systemctl enable ghostcp

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}       Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Next steps:"
echo -e "1. Build GhostCP: ${YELLOW}cd /data/projects/GhostCP && cargo build --release${NC}"
echo -e "2. Copy binary: ${YELLOW}cp target/release/ghostcp-api /opt/ghostcp/${NC}"
echo -e "3. Run migrations: ${YELLOW}cd api && sqlx migrate run${NC}"
echo -e "4. Start service: ${YELLOW}systemctl start ghostcp${NC}"
echo -e "5. Access panel: ${GREEN}https://$HOSTNAME:2083${NC}"
echo ""
echo -e "${YELLOW}Default credentials:${NC}"
echo -e "Username: admin"
echo -e "Password: changeme (please change immediately)"
echo ""
echo -e "${RED}IMPORTANT: This is a self-signed certificate.${NC}"
echo -e "${RED}Replace it with a proper certificate from Let's Encrypt.${NC}"