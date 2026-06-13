# Requirements

## Operating system

GhostCP targets **Debian/Ubuntu** hosts (the installer design assumes
`apt`-based systems), consistent with the HestiaCP lineage. Other distributions
may work when building from source but are not a primary target.

A dedicated host or VM is strongly recommended — GhostCP manages system services
(NGINX, PHP-FPM, BIND/PowerDNS, Postfix, Dovecot) directly.

## Hardware

Minimums for a small single-host deployment:

| Resource | Minimum | Notes |
|----------|---------|-------|
| CPU | 1 core | 2+ recommended |
| RAM | 1 GB | 2 GB+ with mail + DNS + DB |
| Disk | 10 GB | plus site/mail/backup data |

## Software prerequisites

- **PostgreSQL 16** — the control-plane system-of-record
- **Rust toolchain** — to build from source (2024 edition, current stable)
- The managed services you intend to use: NGINX, PHP-FPM, BIND or PowerDNS,
  Postfix, Dovecot

## Network

- Inbound 80/443 for web and ACME HTTP-01.
- Inbound 53 (TCP/UDP) if serving authoritative DNS; 53 to secondaries for
  AXFR/IXFR (TSIG-authenticated) — see
  [authoritative interop](../dns/authoritative-interop.md).
- Inbound 25/465/587/143/993 if hosting mail.
- The control-plane API behind a [reverse proxy](reverse-proxy.md) for TLS.
