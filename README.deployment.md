# GhostCP Production Deployment Guide

## Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/ghostcp.git
   cd ghostcp
   ```

2. **Run the deployment script**:
   ```bash
   ./scripts/deploy.sh your-domain.com admin@your-domain.com
   ```

3. **Access your panel**:
   - Admin Panel: `https://your-domain.com:2083`
   - API Documentation: `https://your-domain.com:2083/api/docs`

## Prerequisites

- Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum, 8GB recommended
- 20GB disk space minimum
- Domain name pointed to your server

## Manual Deployment

### 1. Environment Setup

```bash
# Copy environment template
cp .env.production .env

# Edit configuration
nano .env
```

### 2. Generate Security Keys

```bash
# Generate JWT secret
openssl rand -base64 32

# Generate encryption keys
openssl rand -base64 32
openssl rand -base64 32
```

### 3. Start Services

```bash
# Development
docker-compose -f docker-compose.dev.yml up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

### 4. Initialize Database

```bash
# Run migrations
docker-compose exec ghostcp-api ghostcp-migrate

# Create admin user
docker-compose exec ghostcp-api ghostcp-admin create-user \
  --username admin \
  --email admin@your-domain.com \
  --password your-secure-password \
  --role admin
```

## Service Architecture

### Core Services
- **ghostcp-api**: Rust API server (Port 8080)
- **ghostcp-ui**: Leptos SSR frontend (Port 3000)
- **nginx**: Reverse proxy and web server (Ports 80, 443, 2083)
- **postgres**: PostgreSQL database
- **redis**: Cache and session store

### Mail Services
- **stalwart-mail**: Modern mail server (Ports 25, 587, 143, 993)

### Monitoring Stack
- **prometheus**: Metrics collection (Port 9090)
- **grafana**: Monitoring dashboards (Port 3000)
- **loki**: Log aggregation (Port 3100)
- **promtail**: Log collection agent

### Backup Services
- **backup-runner**: Automated backup jobs
- **restic**: Backup tool with multiple backends

## Configuration

### DNS Records

Set up the following DNS records:

```
A     your-domain.com        → YOUR_SERVER_IP
A     *.your-domain.com      → YOUR_SERVER_IP
A     mail.your-domain.com   → YOUR_SERVER_IP
MX    your-domain.com        → 10 mail.your-domain.com
TXT   your-domain.com        → "v=spf1 mx a ~all"
TXT   _dmarc.your-domain.com → "v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain.com"
```

### SSL Certificates

#### Option 1: Let's Encrypt (Recommended)
```bash
# Install certbot
sudo apt install certbot

# Get certificates
sudo certbot certonly --webroot \
  -w /var/www/.well-known/acme-challenge \
  -d your-domain.com \
  -d *.your-domain.com \
  -d mail.your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/ghostcp/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/ghostcp/ssl/
```

#### Option 2: Self-signed (Development)
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/ghostcp/ssl/ghostcp-admin.key \
  -out /opt/ghostcp/ssl/ghostcp-admin.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

### Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 2083/tcp    # GhostCP Admin
sudo ufw allow 25/tcp      # SMTP
sudo ufw allow 587/tcp     # SMTP Submission
sudo ufw allow 143/tcp     # IMAP
sudo ufw allow 993/tcp     # IMAPS
sudo ufw enable

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=2083/tcp
sudo firewall-cmd --permanent --add-port=25/tcp
sudo firewall-cmd --permanent --add-port=587/tcp
sudo firewall-cmd --permanent --add-port=143/tcp
sudo firewall-cmd --permanent --add-port=993/tcp
sudo firewall-cmd --reload
```

## Backup Configuration

### S3-Compatible Storage

```bash
# AWS S3
BACKUP_AWS_ACCESS_KEY_ID=AKIA...
BACKUP_AWS_SECRET_ACCESS_KEY=...
BACKUP_AWS_REGION=us-east-1
BACKUP_S3_BUCKET=your-backup-bucket

# Wasabi
BACKUP_AWS_ACCESS_KEY_ID=your-wasabi-key
BACKUP_AWS_SECRET_ACCESS_KEY=your-wasabi-secret
BACKUP_AWS_REGION=us-east-1
BACKUP_S3_ENDPOINT=s3.wasabisys.com

# MinIO
BACKUP_S3_ENDPOINT=your-minio-server:9000
BACKUP_AWS_ACCESS_KEY_ID=minioadmin
BACKUP_AWS_SECRET_ACCESS_KEY=minioadmin
```

### Local Backup

```bash
# Create backup directory
sudo mkdir -p /backup/ghostcp
sudo chown ghostcp:ghostcp /backup/ghostcp

# Set in .env
BACKUP_LOCAL_PATH=/backup/ghostcp
```

## Monitoring

### Grafana Dashboards

Access Grafana at `http://your-domain.com:3000`

Default dashboards include:
- System Overview
- GhostCP API Metrics
- Mail Server Statistics
- Backup Status
- Security Events

### Prometheus Metrics

Key metrics monitored:
- API response times
- Database connections
- Mail queue size
- Backup success rates
- SSL certificate expiration
- Disk usage
- Memory usage

### Log Management

Logs are collected by Promtail and stored in Loki:
- Application logs: `/var/log/ghostcp/`
- NGINX logs: `/var/log/nginx/`
- Mail logs: `/var/log/mail.log`
- System logs: `/var/log/syslog`

## Maintenance

### Daily Tasks

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f --tail=100

# Update containers
docker-compose pull && docker-compose up -d
```

### Weekly Tasks

```bash
# Clean up Docker
docker system prune -f

# Check backup integrity
docker-compose exec backup-runner restic check

# Review security logs
docker-compose logs nginx | grep -E "(40[0-9]|50[0-9])"
```

### Monthly Tasks

```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Rotate log files
sudo logrotate -f /etc/logrotate.d/ghostcp

# Review monitoring alerts
# Check Grafana dashboards for anomalies
```

## Troubleshooting

### Common Issues

#### Service won't start
```bash
# Check logs
docker-compose logs service-name

# Check configuration
docker-compose config

# Restart service
docker-compose restart service-name
```

#### Database connection issues
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready

# Reset database password
docker-compose exec postgres psql -U postgres -c "ALTER USER ghostcp PASSWORD 'new-password';"
```

#### SSL certificate issues
```bash
# Check certificate validity
openssl x509 -in /opt/ghostcp/ssl/ghostcp-admin.pem -text -noout

# Renew Let's Encrypt certificate
sudo certbot renew
```

#### Mail delivery issues
```bash
# Check mail server logs
docker-compose logs stalwart-mail

# Test SMTP connection
telnet your-domain.com 25

# Check DNS records
dig MX your-domain.com
dig TXT your-domain.com
```

### Performance Tuning

#### Database Optimization
```sql
-- Monitor slow queries
SELECT query, mean_time, calls
FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 10;

-- Optimize PostgreSQL settings in docker-compose.yml
```

#### NGINX Optimization
```nginx
# Increase worker connections
worker_connections 4096;

# Enable caching
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m;
```

## Security

### Security Checklist

- [ ] Change all default passwords
- [ ] Enable fail2ban for SSH
- [ ] Configure SSL certificates
- [ ] Set up firewall rules
- [ ] Enable audit logging
- [ ] Configure backup encryption
- [ ] Set up monitoring alerts
- [ ] Regular security updates
- [ ] Review access logs

### Hardening Steps

```bash
# Disable root SSH login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Install fail2ban
sudo apt install fail2ban

# Configure automatic updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

## Support

- **Documentation**: https://docs.ghostcp.com
- **GitHub Issues**: https://github.com/your-org/ghostcp/issues
- **Community**: https://discord.gg/ghostcp
- **Professional Support**: support@ghostcp.com

## License

GhostCP is licensed under the MIT License. See `LICENSE` file for details.