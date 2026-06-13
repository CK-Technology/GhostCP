# Changelog

All notable changes to GhostCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Documentation for security and observability integrations (design/planned):
  CrowdSec IPS (NGINX + firewall bouncers, central LAPI, blocklist mirror)
  modernizing fail2ban; external threat-feed import; observability shipping to a
  central Loki/Prometheus/Grafana stack with Wazuh SIEM; Tailscale-private admin
  plane; and Dev↔Prod distributed topology.

## [0.1.0] - 2026-06-13

First tagged baseline. The control plane, authentication, and DNS subsystem are
functional; web/mail/database/backup managers are scaffolded. This release also
covers a project-wide polish pass: dependency modernization, a clean docs tree,
and a dev/test Docker layout.

### Added
- Axum control-plane API (`ghostcp-api`) with PostgreSQL system-of-record and
  SQLx migrations.
- Authentication: JWT sessions, Argon2 password hashing, and TOTP two-factor
  authentication with single-use backup recovery codes.
- DNS subsystem: zone and record CRUD, sync, AXFR, and DNSSEC, with provider
  drivers for Cloudflare, PowerDNS, and local BIND.
- Monitoring: system metrics with a Prometheus scrape endpoint
  (`/api/v1/metrics`).
- Leptos 0.8 web UI (`ghostcp-ui`) with SSR and WASM hydration scaffolding.
- Tera templates for NGINX, PHP-FPM, Postfix, and Dovecot.
- Scaffolded routes and schema for web domains, mail, databases, SSL/ACME,
  cron, backups, and jobs.
- `docker/` dev/test stack (PostgreSQL + API) using host networking.
- Documentation tree under `docs/` plus root `SECURITY.md`, `CONTRIBUTING.md`,
  and this changelog.

### Changed
- Upgraded the Rust workspace to edition 2024 and modernized the dependency tree
  to current major versions:
  - Leptos 0.6 → 0.8 (UI rewritten to the new reactive and router APIs).
  - Axum 0.7 → 0.8 (route parameter syntax updated).
  - SQLx → 0.8, rand → 0.9, thiserror → 2, tower 0.5 / tower-http 0.6,
    reqwest 0.12, and related crates.
  - `trust-dns-resolver` → `hickory-resolver`.
- README rewritten with an accurate implemented-vs-scaffolded status table and
  standards-based DNS / static-site + WordPress positioning.
- Documentation reorganized into a topic-based `docs/` tree; cloud-specific
  (AWS/GCP/Azure/Kubernetes) deployment content removed in favor of the
  host-install model.

### Fixed
- `static mut` API client replaced with `OnceLock` (edition 2024 compliance).
- `base64::encode` calls migrated to the non-deprecated `Engine` API in the ACME
  drivers.
- SQLx queries reconciled with the schema; missing NGINX/PHP-FPM templates added.

### Security
- `cargo audit` exits clean. Resolved advisories from the pre-upgrade dependency
  tree (including the SQLx `RUSTSEC-2024-0363` binary-protocol advisory) by
  upgrading. Remaining entries are compile-time-only `unmaintained` warnings from
  Leptos macro transitive dependencies, documented in `.cargo/audit.toml`.

[Unreleased]: https://github.com/your-org/ghostcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/ghostcp/releases/tag/v0.1.0
