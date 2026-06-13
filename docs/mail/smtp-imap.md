# SMTP / IMAP

The intended mail stack is the standard open-source pairing:

- **Postfix** — SMTP (inbound/outbound mail transfer)
- **Dovecot** — IMAP/POP3 (mailbox access) and SASL authentication

GhostCP renders configuration for both from Tera templates
(`api/src/templates/postfix.rs`, `api/src/templates/dovecot.rs`) driven by the
mail domain/account records in PostgreSQL.

## Model

- A **mail domain** maps to a virtual mail domain in Postfix/Dovecot.
- A **mail account** maps to a virtual mailbox with its own credentials and
  (optionally) quota.

Hostname and DKIM key size are configured via `MAIL_SERVER_HOSTNAME` and
`DKIM_KEY_SIZE` — see [configuration](../getting-started/configuration.md).

## TLS

Mail services use certificates issued through [ACME](../dns/acme.md), the same
issuance path as web TLS.

## Status

Templates and routes exist; provisioning onto a running Postfix/Dovecot
deployment is staged. See the [status table](../../README.md#status).
