# DNSSEC

DNSSEC adds origin authentication and integrity to a zone by signing its records.
GhostCP can enable DNSSEC on a managed zone and handle the signing keys.

## Enabling

```bash
curl -X POST http://localhost:8080/api/v1/dns/{id}/dnssec \
  -H 'Authorization: Bearer <token>'
```

This signs the zone and produces the key material the parent zone needs.

## Key model

DNSSEC uses two key roles:

- **KSK** (Key Signing Key) — signs the zone's DNSKEY set; its digest becomes the
  **DS record** published at the parent (your registrar).
- **ZSK** (Zone Signing Key) — signs the individual records in the zone.

## Publishing to the parent

After enabling DNSSEC, submit the generated **DS record** to your domain
registrar (or the parent zone operator). Validation only takes effect once the DS
is present in the parent.

## Interop note

When you run secondaries (see [authoritative interop](authoritative-interop.md)),
sign on the primary and transfer the signed zone via AXFR/IXFR so every
authoritative server serves identical signed data. Avoid signing independently on
multiple servers.

## Status

Zone signing and the `dnssec` route are implemented via the advanced DNS driver.
Automated key rollover scheduling is planned.
