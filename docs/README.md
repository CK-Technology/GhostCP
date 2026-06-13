# GhostCP Documentation

GhostCP is an experimental, host-level hosting control panel written in Rust.
This is the documentation hub. For a project overview and current status, see the
[root README](../README.md).

> **Experimental.** Interfaces and schema change without notice. Several
> subsystems are scaffolded — each page marks what is implemented vs planned.

## Sections

| Section | Contents |
|---------|----------|
| [Getting Started](getting-started/) | [Installation](getting-started/installation.md) · [Configuration](getting-started/configuration.md) · [Quick Start](getting-started/quick-start.md) |
| [Architecture](architecture/) | [Overview](architecture/overview.md) · [Templating](architecture/templating.md) · [Jobs](architecture/jobs.md) |
| [API](api/) | [Reference](api/README.md) · [Authentication](api/authentication.md) |
| [Websites](websites/) | [Static Sites](websites/static-sites.md) · [WordPress](websites/wordpress.md) |
| [DNS](dns/) | [Zones & Records](dns/zones-and-records.md) · [DNSSEC](dns/dnssec.md) · [Authoritative Interop](dns/authoritative-interop.md) · [ACME](dns/acme.md) |
| [Mail](mail/) | SMTP/IMAP, authentication |
| [Databases](databases/) | Database management |
| [Backups](backups/) | Backup configuration |
| [Security](security/) | [RBAC](security/rbac.md) · [Two-Factor Auth](security/two-factor-auth.md) · [Hardening](security/hardening.md) · [CrowdSec](security/crowdsec.md) · [Threat Feeds](security/threat-feeds.md) |
| [Observability](observability/) | [Logging](observability/logging.md) · [Metrics](observability/metrics.md) · [SIEM (Wazuh)](observability/siem-wazuh.md) |
| [Deployment](deployment/) | [Requirements](deployment/requirements.md) · [Install Script](deployment/install-script.md) · [systemd](deployment/systemd.md) · [Tailscale](deployment/tailscale.md) · [Proxmox Firewall](deployment/proxmox-firewall.md) · [Distributed](deployment/distributed.md) |
| [Development](development/) | [Docker](development/docker.md) · [Building](development/building.md) · [Testing](development/testing.md) |

## System at a glance

```
                 ┌──────────────┐
   Browser  ───► │  Leptos UI   │  SSR + WASM hydration
                 └──────┬───────┘
                        │  HTTP (JSON)
                 ┌──────▼───────┐
                 │  Axum API    │  JWT auth, RBAC, jobs
                 │ (ghostcp-api)│
                 └──┬────────┬──┘
          SQLx      │        │   templates + systemd
        ┌───────────▼┐   ┌───▼─────────────────────────┐
        │ PostgreSQL │   │ NGINX · PHP-FPM · BIND/PDNS  │
        │  (truth)   │   │ Postfix · Dovecot · ACME     │
        └────────────┘   └─────────────────────────────┘
```

## Repository layout

```
GhostCP/
├── api/          # Rust/Axum control plane (ghostcp-api)
│   └── src/
│       ├── handlers/   # HTTP route handlers
│       ├── drivers/    # DNS + ACME provider drivers
│       ├── system/     # host service integration
│       ├── auth/       # JWT, Argon2, TOTP
│       └── templates/  # Tera rendering
├── ui/           # Leptos 0.8 web UI (ghostcp-ui)
├── templates/    # NGINX, PHP-FPM, Postfix, Dovecot (Tera)
├── migrations/   # SQLx migrations (PostgreSQL = source of truth)
├── docker/       # dev/test stack only
└── docs/         # this documentation
```

## Conventions

- **PostgreSQL is the source of truth.** Schema changes are migrations.
- **Production = host install** (script + systemd). Docker is dev/test only.
- Versioning lives in the [CHANGELOG](../CHANGELOG.md), not scattered in docs.
