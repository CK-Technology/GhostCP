# DNS

DNS is GhostCP's most complete subsystem. It manages authoritative zones and
records and interoperates with existing nameservers through open standards rather
than a proprietary replication channel.

- [Zones & Records](zones-and-records.md) — managing zones and records
- [DNSSEC](dnssec.md) — signing and key management
- [Authoritative Interop](authoritative-interop.md) — **the headline:** AXFR/IXFR,
  NOTIFY, TSIG, and mixing secondaries (BIND / PowerDNS / Technitium)
- [ACME / Let's Encrypt](acme.md) — DNS-01 & HTTP-01 validation, acme.sh

## Providers

GhostCP ships pluggable DNS drivers (`api/src/drivers/dns/`):

| Driver | Enabled by | Use |
|--------|-----------|-----|
| **local** (BIND-style) | always (dev default) | local zone files at `/tmp/ghostcp-dns` |
| **Cloudflare** | `CLOUDFLARE_API_TOKEN` | Cloudflare-hosted zones |
| **PowerDNS** | `POWERDNS_API_URL` + `POWERDNS_API_KEY` | self-hosted authoritative |
| **advanced** | — | DNSSEC / transfer helpers |

If no provider is configured, the local driver is still initialized so the
subsystem works out of the box in development.

## API

See the [DNS routes](../api/README.md#dns): zone CRUD, record CRUD, `sync`,
`axfr`, and `dnssec`.
