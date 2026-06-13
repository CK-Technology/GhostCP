# Security

How GhostCP authenticates users, controls access, and hardens the hosts it
manages.

- [RBAC](rbac.md) — roles and access control
- [Two-Factor Auth](two-factor-auth.md) — TOTP enrolment and backup codes
- [Hardening](hardening.md) — host and service hardening
- [Audit Logs](audit-logs.md) — recording mutating actions
- [CrowdSec](crowdsec.md) — IPS agent + bouncers, central LAPI, blocklist mirror
- [Threat Feeds](threat-feeds.md) — importing external IP blocklists

For shipping security signal to a central stack (logs, metrics, Wazuh), see
[Observability](../observability/README.md).

For vulnerability reporting and project security policy, see the root
[SECURITY.md](../../SECURITY.md).

## Summary

- Passwords hashed with **Argon2**; never stored in plaintext.
- Stateless **JWT** sessions signed with `JWT_SECRET`.
- Optional **TOTP** two-factor authentication with single-use backup codes.
- Role-based access model (admin / user).
- Parameterized SQLx queries — no string-built SQL.
- Dependencies audited with `cargo audit`.
