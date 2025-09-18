# GhostCP

<div align="center">
  <img src="assets/ghostCP-logo.png" alt="GhostCP Logo" width="600">

**A Rust-powered hosting control panel — HestiaCP reimagined with Leptos + NGINX**

![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)
![Leptos](https://img.shields.io/badge/UI-Leptos%20(SSR%20%2B%20Islands)-blue?logo=leptos)
![DNS](https://img.shields.io/badge/Authoritative%20DNS-enabled-0a86ff?logo=powerdns)
![WordPress](https://img.shields.io/badge/WordPress-Multisite-21759b?logo=wordpress)
![Cloudflare](https://img.shields.io/badge/DNS-Cloudflare-f38020?logo=cloudflare)
![PowerDNS](https://img.shields.io/badge/DNS-PowerDNS-516beb?logo=powerdns)
![ACME](https://img.shields.io/badge/ACME-Let%E2%80%99s%20Encrypt-success?logo=letsencrypt)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

</div>

---

## 🚀 Current Status: Foundation Complete

**Core infrastructure implemented:**
- ✅ **Database Schema**: Complete PostgreSQL schema with all HestiaCP data models
- ✅ **API Foundation**: Rust/Axum API with user management, domains, DNS, mail, etc.
- ✅ **Development Setup**: Docker Compose, environment configs, migration system
- ✅ **Architecture**: Modular design ready for HestiaCP feature parity

**Next steps:**
- 🔄 Leptos UI implementation
- 🔄 NGINX template system with Tera
- 🔄 DNS providers integration (Cloudflare, PowerDNS)
- 🔄 Mail system integration
- 🔄 SSL/ACME automation

---

## Overview

**GhostCP** is a modern, secure, and fast control panel built in **Rust** with a **Leptos** (SSR + islands) Web UI and **NGINX** templating.  
It delivers the full HestiaCP feature set — **websites, WordPress multisite, DNS, mail, databases, backups, SSL** — and adds opinionated defaults: **DNSSEC by default, ACME DNS-01**, **OIDC**, **S3/MinIO Restic backups**, and a clean API-first architecture.

---

## ✨ Features (Hestia++)

### 🌐 Domains & Authoritative DNS
- Full zone/record management, templates, and bulk ops
- **DNSSEC on by default**
- Providers:
  - **PowerDNS API** (self-hosted authoritative)
  - **Cloudflare DNS API**
  - Route53/others (planned)
- **ACME DNS-01 + HTTP-01** (per domain / wildcard)
- ALIAS/ANAME, GeoDNS (where supported), CAA helpers
- Glue/NS helpers and registrar checklists

### 📰 Websites & Applications
- **WordPress Multisite** one-click (subdomain / subdirectory)
- Hardened PHP-FPM pools per site, isolated UNIX users/chroots
- NGINX / OpenResty vhost templates with HTTP/2, HSTS, OCSP stapling
- Ghost blog & static sites; Bedrock mode for WP (optional)
- Auto-TLS (Let's Encrypt) with seamless renewals

### 📧 Mail Hosting
- Postfix + Dovecot + Rspamd (+ ClamAV optional)
- Automatic **SPF, DKIM, DMARC, MTA-STS, TLS-RPT**, ARC
- Aliases, forwards, catch-alls, per-domain policies
- Quotas, inbound/outbound rate limits, greylisting
- Webmail (Roundcube / SnappyMail)

### 🗄️ Databases
- **MySQL/MariaDB + PostgreSQL**
- Per-app DB/users with least-priv grants
- PITR (where supported), logical dumps, scheduled maintenance
- phpMyAdmin / pgAdmin integration

### 💾 Backups & DR
- **Restic → S3/MinIO/Wasabi** (encryption, retention, integrity checks)
- Files + DB + Mailbox backup policies
- Test-restore flows and scratch-host restore

### 🔒 Security & Access
- Rust-first, memory-safe core; TLS everywhere
- RBAC with **OIDC** (Azure Entra, Google, …)
- Audit logs for all mutating actions
- Fail2Ban-style intrusion prevention presets
- Sensible system hardening (noexec/nodev where applicable)

### 🛠️ Control Panel UX
- **Leptos** SSR + islands for fast loads and realtime actions
- Multi-tenant (users, roles, resellers)
- CLI + Web UI
- Metrics/logs ready for Prometheus/Loki/Grafana
- Multi-server clustering with node labels (web/db/mail/dns)

---

## 🧱 Architecture (Rust + Leptos + NGINX)

- **API / Control Plane:** Rust (**axum**, **sqlx**, **tokio**), OpenAPI, JWT/OIDC sessions  
- **Web UI:** **Leptos** (SSR + server actions + islands hydration) + Tailwind  
- **State:** PostgreSQL (tenants, domains, zones, vhosts, certs, jobs, audits)  
- **Templates:** **Tera** for NGINX, PHP-FPM, Postfix/Dovecot/Rspamd snippets  
- **ACME Drivers:** Cloudflare / PowerDNS (DNS-01), fallback HTTP-01 via NGINX challenge vhost  
- **Orchestration:** idempotent jobs with transactional state + systemd wrappers  
- **Observability:** Prometheus exporters + Loki log tail in panel

### NGINX Template Example (Tera)
```nginx
# templates/nginx/vhost.conf.tera
server {
  listen 80;
  server_name {{ domain }};
  {% if force_https %}return 301 https://$host$request_uri;{% else %}
  root {{ webroot }}/public;
  index index.html index.php;
  {% endif %}
}

server {
  listen 443 ssl http2;
  server_name {{ domain }};

  ssl_certificate     {{ cert_fullchain }};
  ssl_certificate_key {{ cert_key }};
  add_header Strict-Transport-Security "max-age=31536000" always;

  root {{ webroot }}/public;
  index index.php index.html;

  {% if is_wp_multisite %}include snippets/wp_multisite.conf;{% else %}
  include snippets/php_fpm_pool_{{ php_version }}.conf;
  {% endif %}

  access_log /var/log/nginx/{{ domain }}.access.log;
  error_log  /var/log/nginx/{{ domain }}.error.log;
}
```

## 📁 Repo Layout

```
ghostcp/
├── api/                  # Rust (axum/sqlx), OpenAPI, OIDC, jobs
├── ui/                   # Leptos app (SSR + islands), Tailwind
├── templates/            # NGINX, PHP-FPM, Postfix/Dovecot/Rspamd (Tera)
├── drivers/              # dns_cloudflare.rs, dns_pdns.rs, acme_*.rs
├── migrations/           # SQLx/Postgres migrations
├── scripts/              # build, dev, apply, nginx: test/reload
├── docs/                 # ADRs, runbooks, threat model
├── archive/hestiacp/     # upstream reference (read-only, no vendoring)
└── README.md
```

## 🛤️ Roadmap

✅ **Core API + DB schema** (tenants, domains, sites, certs, jobs)  
🔄 **DNS module** (PDNS + Cloudflare, DNSSEC, templates)  
🔄 **Websites** (NGINX, PHP-FPM, WordPress multisite + Bedrock)  
🔄 **Mail** (Postfix/Dovecot/Rspamd, DKIM keys, policies)  
🔄 **Backups** (Restic→S3/MinIO, test-restore flows)  
🔄 **UI** (Leptos dashboards, realtime job logs, audit trails, user/site maintenance / dns records / mailboxes / dbs)  
🔄 **OIDC** (Azure Entra, Google Workspace, Github, OIDC, Oauth2 providers)  
🔄 **Clustering** (multi-node, labels, drain/cordon)  
🔄 **Installers** (Debian/Ubuntu), systemd units, health checks, Docker Compose stacks + dockerfiles, PVE helper script for VM/LXC's  
🔄 **Prometheus Grafana integration**  
🔄 **Better Authorative DNS Server functionality than HestiaCP** - PowerDNS integration, Cloudflare, Route53, DNSSEC, Glue /NS helpers, CAA, GeoDNS, AXFR/IXFR, bulk ops, templates  
🔄 **SMTP2Go Direct integration** for outbound email reliability   
🔄 **ACME DNS-01 drivers** - Cloudflare, Powerdns, Route53, others  
🔄 **HTTP and DNS challenge support**   
🔄 **acme.sh integration** for zero depedency ACME client and wildcard support and acme.sh Let's encrypt rate limit avoidance  
🔄 **Let's encrypt standalone support** but acme.sh using lets encrypt as default is preferred   
🔄 **IPv4/IPv6 support** - for multiple IP addresses for vhosts, mail, dns, etc.   
🔄 **Mature and stable API**   
🔄 **Modern Web Interface**   
🔄 **IP Firewall Integration** - UFW/Firewalld/NFTables  
🔄 **RBAC** - Roles based access control for users   
🔄 **Audit Logs** for all actions   
🔄 **Two Factor Authentication (2FA)** - OIDC Providers with 2FA support  
🔄 **System Hardening** - Fail2Ban, noexec/nodev where applicable  
🔄 **crowdsec integration** for advanced intrusion detection and prevention along with crowdsec nginx bouncer, crowdsec ssh bouncer  
🔄 **wazuh integration** for SIEM and log management  

## ⚙️ Getting Started

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd GhostCP

# Copy environment file and configure
cp .env.example .env
# Edit .env with your database settings

# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# API will be available at http://localhost:8080
# Check health: curl http://localhost:8080/health
```

### Manual Development

```bash
# Start PostgreSQL (if not using Docker)
# Configure DATABASE_URL in .env

# Run API server
cd api
cargo run

# Run migrations (automatic on startup)
# API will start on port 8080
```

### API Endpoints

- **Health Check**: `GET /health`
- **Users**: `GET|POST /api/v1/users`
- **Domains**: `GET|POST /api/v1/domains`
- **DNS**: `GET|POST /api/v1/dns`
- **Mail**: `GET|POST /api/v1/mail`
- **Databases**: `GET|POST /api/v1/databases`
- **SSL**: `GET|POST /api/v1/ssl`
- **Backups**: `GET|POST /api/v1/backups`
- **Jobs**: `GET|POST /api/v1/jobs`

---

## 🎯 What's Working Now

✅ **Database Schema**: Full PostgreSQL schema matching HestiaCP functionality  
✅ **API Foundation**: User management with proper models and validation  
✅ **Development Environment**: Docker Compose setup with auto-reload  
✅ **Configuration System**: Environment-based config with sensible defaults  
✅ **Authentication Framework**: Argon2 password hashing, JWT preparation  
✅ **Migration System**: SQLx migrations for database versioning  

## 🔄 Next Steps

1. **Complete DNS Integration** - PowerDNS and Cloudflare API drivers
2. **NGINX Template Engine** - Tera-based vhost generation
3. **Leptos UI** - Modern web interface with server-side rendering
4. **Mail System** - Postfix/Dovecot integration
5. **SSL/ACME** - Automated certificate management

---

*Built with ❤️ in Rust. Powered by Leptos, Axum, PostgreSQL, and the battle-tested wisdom of HestiaCP.*