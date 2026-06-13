# API Reference

GhostCP exposes a JSON HTTP API. All application routes are under `/api/v1`.
The UI and any future CLI are clients of this API.

- [Authentication](authentication.md) — login, JWT, 2FA

> Routes are listed as defined in `api/src/lib.rs`. Endpoints for **scaffolded**
> subsystems exist and respond, but their provisioning logic may be stubbed. The
> [status table](../../README.md#status) is the source of truth for what's wired.

## Base URL

```
http://<host>:<PORT>/api/v1
```

`PORT` defaults to `8080` (see [configuration](../getting-started/configuration.md)).

## Authentication

Protected routes require a JWT in the `Authorization` header:

```
Authorization: Bearer <token>
```

Obtain a token from `POST /api/v1/auth/login`. See [authentication](authentication.md).

## Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness; returns service name and version |

## Public routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Authenticate, receive a JWT |
| POST | `/api/v1/auth/register` | Register a user |
| POST | `/api/v1/auth/refresh` | Refresh a JWT |
| GET | `/api/v1/metrics` | Prometheus metrics (for scrapers) |

## Authenticated routes

### Auth & account

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/logout` | Invalidate the current session |
| GET | `/api/v1/auth/me` | Current user profile |
| POST | `/api/v1/auth/password` | Change password |

### Two-factor (TOTP)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/totp/setup` | Begin TOTP enrolment |
| POST | `/api/v1/auth/totp/verify` | Verify and activate TOTP |
| POST | `/api/v1/auth/totp/disable` | Disable TOTP |
| GET | `/api/v1/auth/totp/status` | TOTP enrolment status |
| POST | `/api/v1/auth/totp/backup-codes` | Generate backup recovery codes |

### Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/users` | List users |
| POST | `/api/v1/users` | Create a user |
| GET | `/api/v1/users/{id}` | Get a user |
| PUT | `/api/v1/users/{id}` | Update a user *(stubbed)* |

### Web domains

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/domains` | List web domains |
| POST | `/api/v1/domains` | Create a web domain |
| GET | `/api/v1/domains/{id}` | Get a web domain |
| POST | `/api/v1/domains/{id}/ssl` | Enable SSL for a domain |

### DNS

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/dns` | List DNS zones |
| POST | `/api/v1/dns` | Create a DNS zone |
| GET | `/api/v1/dns/{id}` | Get a zone |
| GET | `/api/v1/dns/{id}/records` | List records |
| POST | `/api/v1/dns/{id}/records` | Create a record |
| POST | `/api/v1/dns/{id}/sync` | Sync zone to provider |
| POST | `/api/v1/dns/{id}/axfr` | Trigger zone transfer (AXFR) |
| POST | `/api/v1/dns/{id}/dnssec` | Enable DNSSEC |

See [DNS](../dns/) for the subsystem in depth.

### Mail

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/mail` | List mail domains |
| POST | `/api/v1/mail` | Create a mail domain |
| GET | `/api/v1/mail/{id}/accounts` | List mail accounts |
| POST | `/api/v1/mail/{id}/accounts` | Create a mail account |

### Databases

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/databases` | List databases |
| POST | `/api/v1/databases` | Create a database |

### SSL

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/ssl` | List certificates |
| POST | `/api/v1/ssl` | Request a certificate |
| POST | `/api/v1/ssl/{id}/renew` | Renew a certificate |

TLS issuance supports both DNS-01 and HTTP-01 validation — see
[ACME / Let's Encrypt](../dns/acme.md).

### Cron

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/cron` | List cron jobs |
| POST | `/api/v1/cron` | Create a cron job |

### Backups

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/backups` | List backup configs |
| POST | `/api/v1/backups` | Create a backup config |

### Jobs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/jobs` | List system jobs |
| POST | `/api/v1/jobs` | Create a system job |

### Monitoring

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/monitoring/metrics` | Current system metrics |
| GET | `/api/v1/monitoring/history` | Metrics history |
| GET | `/api/v1/monitoring/services` | Service status |
| GET | `/api/v1/monitoring/processes` | Process list |
| GET | `/api/v1/monitoring/disk` | Disk usage |
| GET | `/api/v1/monitoring/network` | Network stats |
| POST | `/api/v1/monitoring/start` | Start metrics collection |

## Conventions

- Request and response bodies are JSON.
- IDs are UUIDs.
- CORS is permissive in the current build (development posture).
