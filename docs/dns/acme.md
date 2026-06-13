# ACME / Let's Encrypt

GhostCP issues TLS certificates via **ACME** (Let's Encrypt by default) and
supports **both** validation methods:

- **DNS-01** — proves control by publishing a TXT record at
  `_acme-challenge.<domain>`. Works behind firewalls and supports **wildcards**.
- **HTTP-01** — proves control by serving a token at
  `http://<domain>/.well-known/acme-challenge/<token>`. Simple for single hosts.

Both are first-class. DNS-01 is preferred for wildcards and for hosts that aren't
publicly reachable on port 80; HTTP-01 is convenient for ordinary single-name
sites.

## Challenge types

The ACME layer (`api/src/drivers/acme/`) models challenge types as:

| Type | Handler | How it validates |
|------|---------|------------------|
| `Dns01` | `dns_challenge.rs` | writes a TXT record via the active [DNS driver](README.md#providers) |
| `Http01` | `http_challenge.rs` | writes a file under the site web root's `.well-known/acme-challenge/` |
| `TlsAlpn01` | — | enum present; not implemented |

Because **DNS-01 reuses GhostCP's DNS drivers**, the same Cloudflare / PowerDNS /
local BIND integration that manages your zones also answers ACME challenges — no
separate credentials.

### DNS-01

1. ACME client requests a challenge; GhostCP computes the `_acme-challenge`
   TXT value.
2. The DNS driver publishes the TXT record in the zone.
3. The CA validates; GhostCP removes the temporary record.

Use this for **wildcard** certificates (`*.example.com`) and for internal hosts.

### HTTP-01

1. ACME client requests a challenge token.
2. GhostCP writes `<webroot>/.well-known/acme-challenge/<token>`.
3. The CA fetches it over HTTP; GhostCP cleans up the file.

Use this for ordinary single-name public sites where port 80 is reachable.

## Clients

### Native ACME client
A built-in Rust ACME client (`api/src/drivers/acme/letsencrypt.rs`) drives the
order/challenge/finalize flow directly against the CA. Supported key types:
RSA-2048/4096 and ECDSA P-256/P-384.

### acme.sh (planned integration)
GhostCP also targets integration with [acme.sh](https://github.com/acmesh-official/acme.sh)
as an external issuance backend. Rationale:

- a battle-tested, zero-dependency client with the widest DNS-provider coverage,
- straightforward wildcard issuance via DNS-01,
- useful for working around per-account rate limits and for environments that
  already standardize on it.

The acme.sh backend would expose the same DNS-01 and HTTP-01 options; GhostCP
supplies the DNS credentials/web root and records the resulting certificate.

## API

Certificate operations are under the [SSL routes](../api/README.md#ssl):

```bash
# request a certificate
curl -X POST http://localhost:8080/api/v1/ssl \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","challenge_type":"dns-01","provider":"letsencrypt"}'

# renew
curl -X POST http://localhost:8080/api/v1/ssl/{id}/renew \
  -H 'Authorization: Bearer <token>'
```

Enabling SSL on a web domain:

```bash
curl -X POST http://localhost:8080/api/v1/domains/{id}/ssl \
  -H 'Authorization: Bearer <token>'
```

## Renewal

Certificates are renewed before expiry (the manager checks a ~30-day window).
Automatic renewal scheduling is staged alongside the [jobs](../architecture/jobs.md)
runtime.

## Status

The challenge handlers, the native Let's Encrypt client, and the SSL routes
exist. End-to-end issuance wiring (account persistence, full key-authorization
hashing, auto-renew worker) and the acme.sh backend are in progress — see the
[status table](../../README.md#status).
