# API Authentication

GhostCP uses stateless **JWT** authentication. Passwords are hashed with
**Argon2**; optional **TOTP** two-factor authentication is supported.

## Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

On success the response contains a signed JWT. Present it on protected routes:

```
Authorization: Bearer <token>
```

The token is signed with `JWT_SECRET` (see
[configuration](../getting-started/configuration.md)). Set a strong secret before
exposing the instance.

## Refresh

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<token>"}'
```

## Current user

```bash
curl http://localhost:8080/api/v1/auth/me \
  -H 'Authorization: Bearer <token>'
```

## Change password

```bash
curl -X POST http://localhost:8080/api/v1/auth/password \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"...","new_password":"..."}'
```

## Two-factor authentication (TOTP)

TOTP enrolment is a setup → verify flow, with single-use backup codes for
recovery. See [security/two-factor-auth](../security/two-factor-auth.md) for the
full walkthrough. The endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/auth/totp/setup` | Start enrolment (returns secret/QR provisioning) |
| POST | `/api/v1/auth/totp/verify` | Confirm a code, activate 2FA |
| GET | `/api/v1/auth/totp/status` | Check whether 2FA is enabled |
| POST | `/api/v1/auth/totp/backup-codes` | Generate recovery codes |
| POST | `/api/v1/auth/totp/disable` | Disable 2FA |

## Authorization

Routes are gated by `auth_middleware`. A role model (admin / user) exists for
authorization; see [security/rbac](../security/rbac.md).
