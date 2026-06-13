# Hardening

GhostCP is a host-level panel, so hardening covers both the control plane and the
services it provisions.

## Control plane

- Set a strong, unique `JWT_SECRET`; rotate if leaked.
- Replace every default credential and `change-me-in-production` value before
  exposing the instance (`ADMIN_PASSWORD`, `BACKUP_ENCRYPTION_KEY`, …) — see
  [configuration](../getting-started/configuration.md).
- Enable [two-factor authentication](two-factor-auth.md) for admin accounts.
- Run the API behind a TLS-terminating reverse proxy in any non-local
  deployment; CORS is permissive in the current development build.
- Keep the **admin panel and SSH off the public internet** — bind them to a
  [Tailscale](../deployment/tailscale.md) interface and expose only public site
  ports.

## Web hosting

- One **PHP-FPM pool per site** running as a dedicated UNIX user, so sites are
  isolated from each other.
- TLS by default via [ACME](../dns/acme.md); HTTP redirects to HTTPS, HSTS set.

## DNS

- Sign zones with [DNSSEC](../dns/dnssec.md).
- Authenticate zone transfers with **TSIG**; restrict `allow-transfer` to known
  secondaries — see [authoritative interop](../dns/authoritative-interop.md).

## Mail

- Publish [SPF, DKIM, DMARC](../mail/authentication.md).
- TLS for SMTP/IMAP via the same ACME issuance path.

## Intrusion prevention & threat feeds

- **[CrowdSec](crowdsec.md)** is the planned IPS layer — agent + NGINX/firewall
  bouncers replacing HestiaCP's fail2ban, with a central LAPI and blocklist
  mirror for fleets.
- **[Threat feeds](threat-feeds.md)** import external IP blocklists (e.g.
  `threat.cktechnology.io/*.txt`) and enforce them at NGINX/nftables to shield
  hosted static and WordPress sites.

## Planned

Firewall integration (UFW/firewalld/nftables) and filesystem mount hardening
(`noexec`/`nodev` where applicable) are planned. Track progress in the
[status table](../../README.md#status).
