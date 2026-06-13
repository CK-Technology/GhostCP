# Configuration

GhostCP reads configuration from the environment. Copy the example file and edit:

```bash
cp .env.example .env
```

## Environment variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://ghostcp:password@localhost/ghostcp` | PostgreSQL connection string |
| `PORT` | `8080` | HTTP listen port for the API |
| `JWT_SECRET` | `change-me-in-production` | Secret used to sign session JWTs |
| `RUST_LOG` | `ghostcp_api=debug,tower_http=debug` | Log filter |

### Initial admin

Created on first run if it does not exist.

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USER` | `admin` | Bootstrap admin username |
| `ADMIN_PASSWORD` | `admin` | Bootstrap admin password |

### System paths

| Variable | Default | Description |
|----------|---------|-------------|
| `TEMPLATES_DIR` | `/etc/ghostcp/templates` | Tera template root |
| `NGINX_CONFIG_DIR` | `/etc/nginx` | NGINX config output |
| `SSL_CERTS_DIR` | `/etc/ghostcp/ssl` | Certificate storage |
| `USER_HOME_DIR` | `/home` | Per-user home base |

### DNS providers (optional)

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | Enables the Cloudflare DNS driver |
| `POWERDNS_API_URL` | PowerDNS API base URL |
| `POWERDNS_API_KEY` | PowerDNS API key |

A **local** BIND-style driver is always initialized for development even when no
provider is configured. See [DNS](../dns/).

### Mail

| Variable | Default | Description |
|----------|---------|-------------|
| `MAIL_SERVER_HOSTNAME` | `mail.example.com` | Mail server hostname |
| `DKIM_KEY_SIZE` | `2048` | DKIM key size |

### Backups

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_BACKUP_BACKEND` | `local` | Backup backend |
| `BACKUP_ENCRYPTION_KEY` | `change-me-in-production` | Backup encryption key |

### Security & resources

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSWORD_MIN_LENGTH` | `8` | Minimum password length |
| `SESSION_TIMEOUT_HOURS` | `24` | Session lifetime |
| `MAX_LOGIN_ATTEMPTS` | `5` | Login attempt cap |
| `DEFAULT_WEB_TEMPLATE` | `default` | Default web vhost template |
| `DEFAULT_PHP_VERSION` | `8.3` | Default PHP-FPM version |
| `NGINX_WORKER_PROCESSES` | `auto` | NGINX worker processes |

> Change every `change-me-in-production` and default credential before exposing
> the instance anywhere. PostgreSQL migrations run automatically on startup.
