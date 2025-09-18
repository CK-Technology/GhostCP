#!/bin/bash
# GhostCP Production Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN=${1:-"your-domain.com"}
ADMIN_EMAIL=${2:-"admin@$DOMAIN"}
ENVIRONMENT=${3:-"production"}

echo -e "${BLUE}🚀 Starting GhostCP deployment for $DOMAIN${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should not be run as root${NC}"
   exit 1
fi

# Check prerequisites
echo -e "${BLUE}📋 Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose first: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if .env file exists
if [[ ! -f .env ]]; then
    echo -e "${YELLOW}⚠️  No .env file found. Creating from template...${NC}"
    cp .env.production .env
    echo -e "${YELLOW}📝 Please edit .env file with your configuration and run this script again${NC}"
    exit 1
fi

# Load environment variables
source .env

# Validate required environment variables
required_vars=(
    "DB_PASSWORD"
    "REDIS_PASSWORD"
    "JWT_SECRET"
    "ENCRYPTION_KEY"
    "BACKUP_ENCRYPTION_KEY"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo -e "${RED}❌ Required environment variable $var is not set${NC}"
        echo "Please configure your .env file properly"
        exit 1
    fi
done

echo -e "${GREEN}✅ Prerequisites check passed${NC}"

# Create required directories
echo -e "${BLUE}📁 Creating required directories...${NC}"
sudo mkdir -p /opt/ghostcp/{ssl,nginx,mail,backups,logs}
sudo mkdir -p /var/log/ghostcp
sudo chown -R $USER:$USER /opt/ghostcp

# Generate SSL certificates directory structure
mkdir -p ssl/{live,archive}

# Create systemd service for Docker Compose
echo -e "${BLUE}🔧 Creating systemd service...${NC}"
sudo tee /etc/systemd/system/ghostcp.service > /dev/null <<EOF
[Unit]
Description=GhostCP Hosting Control Panel
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker-compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker-compose -f docker-compose.prod.yml down
TimeoutStartSec=0
User=$USER

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable ghostcp.service

# Pull Docker images
echo -e "${BLUE}📥 Pulling Docker images...${NC}"
docker-compose -f docker-compose.prod.yml pull

# Build custom images
echo -e "${BLUE}🏗️  Building custom images...${NC}"
docker-compose -f docker-compose.prod.yml build

# Start services
echo -e "${BLUE}🏃 Starting services...${NC}"
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to be healthy
echo -e "${BLUE}⏳ Waiting for services to start...${NC}"
sleep 30

# Check service health
echo -e "${BLUE}🏥 Checking service health...${NC}"
services=("postgres" "redis" "ghostcp-api" "nginx")
for service in "${services[@]}"; do
    if docker-compose -f docker-compose.prod.yml ps $service | grep -q "Up"; then
        echo -e "${GREEN}✅ $service is running${NC}"
    else
        echo -e "${RED}❌ $service failed to start${NC}"
        docker-compose -f docker-compose.prod.yml logs $service
        exit 1
    fi
done

# Run database migrations
echo -e "${BLUE}🗃️  Running database migrations...${NC}"
docker-compose -f docker-compose.prod.yml exec -T ghostcp-api ghostcp-migrate

# Create initial admin user
echo -e "${BLUE}👤 Creating initial admin user...${NC}"
docker-compose -f docker-compose.prod.yml exec -T ghostcp-api ghostcp-admin create-user \
    --username admin \
    --email "$ADMIN_EMAIL" \
    --password "$(openssl rand -base64 12)" \
    --role admin

# Setup firewall rules
echo -e "${BLUE}🔥 Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
    sudo ufw allow 22/tcp      # SSH
    sudo ufw allow 80/tcp      # HTTP
    sudo ufw allow 443/tcp     # HTTPS
    sudo ufw allow 2083/tcp    # GhostCP Admin
    sudo ufw allow 25/tcp      # SMTP
    sudo ufw allow 587/tcp     # SMTP Submission
    sudo ufw allow 143/tcp     # IMAP
    sudo ufw allow 993/tcp     # IMAPS
    sudo ufw --force enable
    echo -e "${GREEN}✅ Firewall configured${NC}"
fi

# Setup log rotation
echo -e "${BLUE}📝 Setting up log rotation...${NC}"
sudo tee /etc/logrotate.d/ghostcp > /dev/null <<EOF
/var/log/ghostcp/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        docker-compose -f $(pwd)/docker-compose.prod.yml restart nginx
    endscript
}
EOF

# Create backup script
echo -e "${BLUE}💾 Setting up backup cron job...${NC}"
cat > /tmp/ghostcp-backup.sh << 'EOF'
#!/bin/bash
# GhostCP Backup Script
cd /opt/ghostcp
docker-compose -f docker-compose.prod.yml exec -T backup-runner /usr/local/bin/run-backups
EOF

sudo mv /tmp/ghostcp-backup.sh /usr/local/bin/ghostcp-backup.sh
sudo chmod +x /usr/local/bin/ghostcp-backup.sh

# Add to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/ghostcp-backup.sh") | crontab -

# Setup monitoring alerts
echo -e "${BLUE}📊 Setting up monitoring...${NC}"
# This would typically involve configuring Prometheus rules and Grafana dashboards

# Print deployment summary
echo -e "${GREEN}🎉 GhostCP deployment completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Deployment Summary:${NC}"
echo "• Domain: $DOMAIN"
echo "• Admin Panel: https://$DOMAIN:2083"
echo "• Admin Email: $ADMIN_EMAIL"
echo "• Services: $(docker-compose -f docker-compose.prod.yml ps --services | wc -l) containers running"
echo ""
echo -e "${BLUE}🔧 Next Steps:${NC}"
echo "1. Configure your DNS records to point to this server"
echo "2. Set up SSL certificates (Let's Encrypt recommended)"
echo "3. Configure your mail server settings"
echo "4. Set up backup destinations"
echo "5. Review monitoring dashboards at http://localhost:3000"
echo ""
echo -e "${BLUE}📚 Documentation:${NC}"
echo "• API Documentation: https://$DOMAIN:2083/api/docs"
echo "• User Guide: https://docs.ghostcp.com"
echo "• Support: https://github.com/your-org/ghostcp/issues"
echo ""
echo -e "${YELLOW}⚠️  Important Security Notes:${NC}"
echo "• Change default passwords in .env file"
echo "• Configure SSL certificates for production use"
echo "• Regularly update Docker images"
echo "• Monitor system logs and alerts"
echo ""
echo -e "${GREEN}✨ GhostCP is ready! Happy hosting! ✨${NC}"