# Security Policy

GhostCP is a host-level control panel that provisions privileged services
(web, DNS, mail, TLS) on the systems it manages. Security is therefore central
to the project. This document explains how to report vulnerabilities and what
practices the project follows.

> **Note:** GhostCP is experimental and not yet recommended for production use.
> Treat any deployment as a lab environment.

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Instead, report privately through one of:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab)
- A direct message to the maintainers

When reporting, please include:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof of concept
- Affected component(s) and version/commit
- Any suggested remediation, if known

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement of report | within 72 hours |
| Initial assessment & severity | within 7 days |
| Fix or mitigation plan | depends on severity and complexity |
| Public disclosure | coordinated, after a fix is available |

These are good-faith targets for an experimental project, not contractual SLAs.

## Supported Versions

GhostCP is pre-1.0. Only the latest commit on the default branch receives
security fixes. Tagged releases prior to the current one are not maintained.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| older tags | ❌ |

## Security Practices

### Authentication & access control
- Passwords hashed with **Argon2** (password-hash crate); plaintext is never stored.
- Sessions issued as **JWTs**; the signing secret is supplied via `JWT_SECRET`.
- **TOTP two-factor authentication** with single-use backup recovery codes.
- A role-based access model (admin / user) gates privileged operations.

### Data protection
- PostgreSQL is the system-of-record; access is via parameterized SQLx queries,
  which avoids SQL injection by construction.
- Secrets (DB URL, JWT secret, provider API tokens) are read from the
  environment, never committed. See `.env.example` for the variable list.

### Dependency auditing
- The dependency tree is checked with [`cargo audit`](https://github.com/rustsec/rustsec).
- Reviewed, intentionally-ignored advisories are documented with written
  justification in [`.cargo/audit.toml`](.cargo/audit.toml).
- `cargo audit` is expected to exit clean (no unaddressed vulnerabilities).

### Host hardening
GhostCP templates native services and is intended to apply sensible hardening
defaults (isolated PHP-FPM pools and UNIX users per site, TLS-by-default for web
and mail, DNSSEC for zones). Hardening guidance is collected under
[docs/security/](docs/security/).

## Disclosure Policy

We follow **coordinated disclosure**. Please give the project a reasonable window
to ship a fix before any public discussion of a vulnerability. We will credit
reporters who wish to be acknowledged.
