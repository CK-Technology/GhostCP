# Two-Factor Authentication (TOTP)

GhostCP supports **TOTP** two-factor authentication (RFC 6238) — the standard
authenticator-app codes — with single-use **backup recovery codes**.

## Enrolment

1. **Setup.** Begin enrolment to obtain a shared secret and a provisioning URI
   (renderable as a QR code):

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/totp/setup \
     -H 'Authorization: Bearer <token>'
   ```

   Scan the QR / enter the secret in an authenticator app (Aegis, 1Password,
   Google Authenticator, …).

2. **Verify.** Confirm a code from the app to activate 2FA:

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/totp/verify \
     -H 'Authorization: Bearer <token>' \
     -H 'Content-Type: application/json' \
     -d '{"code":"123456"}'
   ```

## Backup codes

Generate single-use recovery codes for when the authenticator device is
unavailable. Store them somewhere safe; each works once.

```bash
curl -X POST http://localhost:8080/api/v1/auth/totp/backup-codes \
  -H 'Authorization: Bearer <token>'
```

## Status & disable

```bash
# is 2FA enabled?
curl http://localhost:8080/api/v1/auth/totp/status \
  -H 'Authorization: Bearer <token>'

# disable 2FA
curl -X POST http://localhost:8080/api/v1/auth/totp/disable \
  -H 'Authorization: Bearer <token>'
```

## Storage

TOTP secrets and backup codes are persisted in the `002_totp_secrets` schema.
This subsystem is implemented.
