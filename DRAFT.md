# GhostCP – Next Gen Features & Improvements (Draft)

This document is a living draft of features, improvements, and architectural decisions
that make **GhostCP** a secure, modern, Rust-powered alternative to HestiaCP.

---

## 🔄 Backups & Disaster Recovery
- Native **Restic** integration with pluggable backends:
  - S3/MinIO, Wasabi, Backblaze B2, local filesystem.
- Per-tenant backup policies (daily/weekly/monthly).
- **Integrity checks** and automatic **test-restore** jobs.
- "Restore to scratch" workflow (spin up a test WordPress/DB from backup).
- Retention rules with pruning (e.g. `7 daily / 4 weekly / 12 monthly`).

---

## 🛡️ Security & Hardening
- Built-in **CrowdSec agent** with scenarios for:
  - NGINX, Postfix, Dovecot, SSH.
  - Shared ban lists across multi-node clusters.
- Default **TLS everywhere** (panel, mail, API, web).
- **MTA-STS** + **TLS-RPT** policy generation.
- BIMI key management for modern mail branding.
- Hardened PHP presets:
  - Disabled dangerous functions.
  - Per-pool chroot + seccomp profiles.
  - Resource quotas (CPU/mem/IO).

---

## 🔑 Certificates & ACME
- **acme.sh** driver model for certificate issuance.
  - Cloudflare DNS-01.
  - PowerDNS API.
  - HTTP-01 fallback with NGINX challenge vhost.
  - Optional EAB (for ZeroSSL, BuyPass).
- Smart wildcard issuance (per zone).
- Per-service certificates (mail, panel, web, API).
- Automatic renewals + reload hooks.

---

## 🌐 DNS as a First-Class Feature
- Authoritative DNS with **DNSSEC enabled by default**.
- Multi-provider support:
  - PowerDNS API (self-hosted).
  - Cloudflare API.
  - Route53, DigitalOcean (future).
- Zone templates for SaaS:
  - Microsoft 365.
  - Google Workspace.
  - GitHub Pages.
- Glue/NS record helpers with registrar validation.
- Registrar sync tools (where API available).

---

## 📊 Observability & Monitoring
- **Prometheus exporters**:
  - NGINX, Postfix, Dovecot, Restic jobs.
- **Loki log streaming** into panel.
- Built-in system dashboards (CPU, RAM, disk, SSL expiry, mail queue).
- Alerts & webhooks for job failures or quota breaches.

---

## 📰 Applications & Web Hosting
- WordPress Multisite (subdomain/subdirectory).
- Bedrock-based WordPress option (immutable core).
- Ghost blog support.
- Static site hosting.
- Git-based deployments (GitHub/Gitea/Forgejo hooks).
- Built-in caching recipes (Redis, FastCGI cache).

---

## 👥 Multi-Tenancy & Authentication
- OIDC authentication (Azure Entra, Google, etc).
- RBAC roles: Owner, Admin, Reseller, Tenant, Viewer.
- Tenant quotas (sites, mailboxes, DBs, disk, bandwidth).
- Self-service password reset + 2FA (TOTP/WebAuthn).

---

## 🔄 Clustering & Scale
- Multi-node clusters with node labels (web, db, mail, dns).
- Node lifecycle:
  - Drain/cordon for upgrades.
  - Auto-join workflow.
- DNS and mail replication across nodes.
- Remote job execution via API channels.

---

## 🛠️ Usability & Automation
- Self-healing jobs:
  - Detect NGINX/SSL/DNS drift → reconcile automatically.
- “Recipes” for stacks:
  - WP+Redis.
  - Ghost+Postgres.
  - Static+Cloudflare.
- Migration wizard:
  - Import from Hestia, cPanel, Plesk.
- Contextual help/docs built into panel.
- API-first CLI (`ghostcp site add`, `ghostcp dns zone create`).

---

## 📂 Repo Enhancements
- Reference archive (`archive/hestiacp`) for study.
- `templates/` for NGINX, Postfix, Dovecot, Rspamd (Tera-based).
- Modular driver system:
  - DNS (Cloudflare, PDNS).
  - ACME.
  - Backups (Restic repos).

---

📧 Mail Improvements

Per-domain outbound relays (Amazon SES, Mailgun, Postmark).

Mailing lists integration (Mailman-lite or Sympa).

Easy DKIM key rollover with scheduled activation.

Mail reputation monitoring (Spamhaus, MXToolbox lookups).

--- 
🧭 Networking / Access

Built-in Tailscale/Headscale integration
Nodes join a secure overlay automatically. Panel can expose services only via tailnet.

Zero-trust SSH/SFTP
Replace direct SSH with web-based console and Tailscale ACLs.

Reverse proxy recipes
Pre-canned NGINX templates for Node, Python, Go apps — not just PHP.

Built-in WireGuard VPN profiles
Issue per-user VPN configs directly from panel.

--- 

Recipe/Plugin system
Drop-in YAML/TOML recipes for new stacks (e.g. WP+Redis+Varnish).

API & webhooks
Trigger external systems on job complete (CI/CD, alerts).

CLI parity
Everything doable via CLI (ghost site add, ghostcp backup run).

Security / Network	Zero-trust SSH / SFTP gateway (internally via panel + Tailscale)	Reduces attack surface, removes need for port forwarding or open SSH ports.
	Honest WAF integration, e.g. ModSecurity + custom rules, or a Rust-based WAF plugin	Adds protection for app vulnerability attacks.
Storage & Files	Support for object storage for media uploads in WP/Ghost (S3/MinIO)	Scalability and offloading; helps with large media sites.
	Auto-cleanup of orphaned files, cache pruning, log rotation policies	Keeps system tidy; saves disk.
Networking / CDN	Outbound IPv6 support; IPv6 for mail / panel / web	Modern requirement; many providers rely on IPv6.
	Optional CDN integration (Cloudflare, BunnyCDN, Netlify, etc.) via built-in config templates


## 🚀 Stretch Goals
- Built-in GitOps mode (sync config via Git repo).
- ZFS/Btrfs snapshot integration for ultra-fast rollback.
- Optional k8s operator for container-native deployments.
- GUI marketplace for community recipes.

