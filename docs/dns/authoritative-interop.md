# Authoritative DNS Interoperability

This is GhostCP's headline DNS capability: a GhostCP primary nameserver
interoperates with **any** standards-compliant authoritative server as a
secondary, using the open protocols every DNS implementation already speaks —
**AXFR/IXFR**, **NOTIFY**, and **TSIG**.

You are not locked into one vendor's clustering. Run `ns1` on GhostCP and `ns2`
on PowerDNS, BIND, or Technitium; they stay in sync over the wire.

## Why this approach

HestiaCP keeps secondaries in sync by rsync-ing zone files between boxes over
SSH. That works, but it is GhostCP-to-GhostCP only, file-format-coupled, and
opaque to the DNS protocol. GhostCP instead uses the mechanisms DNS was designed
with:

| Concern | HestiaCP rsync model | GhostCP standards model |
|---------|----------------------|--------------------------|
| Transport | SSH file copy | DNS AXFR/IXFR |
| Change push | cron / manual | NOTIFY (immediate) |
| Authentication | SSH keys | TSIG (per-zone shared key) |
| Incremental | full file | IXFR (deltas) |
| Secondary software | must be Hestia | any RFC-compliant server |

The result: mix-and-match secondaries, immediate propagation, authenticated
transfers, and no proprietary coupling.

## Reference layout

A clean split of authoritative and recursive duties:

```
                      ┌──────────────────────────────┐
   registrar  ──DS──► │  ns1  (GhostCP primary)      │
                      │  BIND9 authoritative + DNSSEC│
                      └───────┬──────────────────────┘
                       NOTIFY │  AXFR/IXFR (TSIG)
                              ▼
        ┌─────────────────────┬─────────────────────┐
        │ ns2 PowerDNS        │ ns3 BIND / Technitium│
        │ (secondary)         │ (secondary)          │
        └─────────────────────┴─────────────────────┘

   Resolution for hosted apps:  Unbound (recursive, validating)
```

- **Authoritative:** BIND9 on the primary, signing zones with DNSSEC.
- **Recursive/validating:** Unbound, separate from the authoritative service.
- **Secondaries:** any compliant server pulling via AXFR/IXFR.

## How it works

1. **Primary holds the signed zone.** GhostCP renders the zone from PostgreSQL
   and (optionally) signs it with DNSSEC.
2. **NOTIFY on change.** When the zone's serial increments, the primary sends a
   DNS NOTIFY to each secondary so they refresh immediately instead of waiting
   for the SOA refresh timer.
3. **Secondaries transfer via AXFR/IXFR.** They pull the full zone (AXFR) or just
   the delta since their last serial (IXFR).
4. **TSIG authenticates the transfer.** A per-zone shared key signs NOTIFY and
   transfer requests so only authorized secondaries can pull.

GhostCP exposes the transfer trigger at:

```bash
curl -X POST http://localhost:8080/api/v1/dns/{id}/axfr \
  -H 'Authorization: Bearer <token>'
```

## Example: GhostCP primary, PowerDNS secondary

On the GhostCP/BIND primary, allow transfer and notify the secondary, keyed with
TSIG:

```
key "ns2.example.com" {
    algorithm hmac-sha256;
    secret "<base64-tsig-secret>";
};

zone "example.com" {
    type master;
    file "/etc/ghostcp/dns/example.com.zone";
    allow-transfer { key "ns2.example.com"; };
    also-notify { 203.0.113.2 key "ns2.example.com"; };
};
```

On PowerDNS (secondary), register the zone as a slave with the matching TSIG key
(`pdnsutil` / API), pointing at the GhostCP primary as master. PowerDNS will
accept the NOTIFY and pull via AXFR/IXFR.

The same pattern works with a BIND or Technitium secondary — only the config
syntax differs; the protocol is identical.

## DNSSEC across secondaries

Sign **once on the primary** and transfer the signed zone. Every secondary then
serves identical signed records. Submit the DS record from the primary to your
registrar. See [DNSSEC](dnssec.md).

## Status

Zone management, the `sync`/`axfr`/`dnssec` routes, and the local/Cloudflare/
PowerDNS drivers are implemented. The BIND/Unbound reference deployment and TSIG
key automation are documented here as the target operational model; some of the
glue (automatic TSIG provisioning, secondary registration helpers) is staged.
