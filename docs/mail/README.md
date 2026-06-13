# Mail

GhostCP models mail hosting as **mail domains** and **mail accounts**, intended to
be provisioned onto a Postfix (SMTP) + Dovecot (IMAP) stack.

- [SMTP / IMAP](smtp-imap.md) — the mail stack
- [Authentication](authentication.md) — SPF, DKIM, DMARC

## API

See the [mail routes](../api/README.md#mail):

```bash
# create a mail domain
curl -X POST http://localhost:8080/api/v1/mail \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# create an account in a domain
curl -X POST http://localhost:8080/api/v1/mail/{id}/accounts \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"address":"user@example.com","password":"..."}'
```

## Status

Mail domain/account routes and schema exist; `templates/` rendering modules for
Postfix and Dovecot are present (`api/src/templates/postfix.rs`, `dovecot.rs`).
End-to-end provisioning onto a live mail stack is **scaffolded** — see the
[status table](../../README.md#status).
