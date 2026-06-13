# Architecture Overview

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

## Components

### Control plane — `api/` (`ghostcp-api`)
An Axum service. Responsibilities:

- Authentication (JWT), authorization (RBAC), TOTP 2FA — see [auth](../security/)
- Resource handlers under `api/src/handlers/` (users, domains, dns, mail,
  databases, ssl, cron, backups, jobs, monitoring, two-factor)
- DNS and ACME provider drivers under `api/src/drivers/`
- Host service integration under `api/src/system/`
- Tera template rendering under `api/src/templates/`

The router is defined in `api/src/lib.rs` (`create_router`). The binary entry
point `api/src/main.rs` wires configuration, the database pool, DNS providers,
and serving.

### Web UI — `ui/` (`ghostcp-ui`)
Leptos 0.8 application with server-side rendering and WASM hydration. It is a
client of the HTTP API.

### State — PostgreSQL
The single source of truth. Schema is owned by SQLx migrations under
`migrations/`. Three migrations exist today:

- `001_initial_schema` — core tables (users, domains, DNS, mail, databases, etc.)
- `002_totp_secrets` — 2FA secrets and backup codes
- `003_monitoring_tables` — metrics history

### Service layer
Native services GhostCP templates and drives: NGINX, PHP-FPM, BIND/PowerDNS,
Postfix, Dovecot, and ACME (Let's Encrypt). See [templating](templating.md).

## Request flow

1. The UI (or any API client) sends an HTTP request with a Bearer JWT.
2. `auth_middleware` validates the token on protected routes.
3. The handler reads/writes PostgreSQL through SQLx.
4. For provisioning actions, the handler renders templates and applies them to
   native services (this wiring is complete for DNS; web/mail/ssl are staged).

## Implementation status

The DNS subsystem, authentication, and monitoring are functional. Web, mail,
database, SSL, cron, backup, and job handlers have routes and schema but stubbed
provisioning logic. See the [README status table](../../README.md#status).
