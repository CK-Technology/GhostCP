# Install Script (design)

> **Planned.** This page is the *design* of the production installer. It is not
> yet implemented. Until it ships, deploy by building from source and wiring
> [systemd](systemd.md) units by hand.

The goal is a single, idempotent `install.sh` in the HestiaCP tradition — run one
command on a fresh Debian/Ubuntu host and get a working GhostCP — but modernized:
declarative, re-runnable, and systemd-native.

## Principles

- **Single entry point.** `curl … | bash` or a downloaded `install.sh`.
- **Idempotent.** Safe to re-run; converges to the desired state instead of
  failing on existing resources.
- **Distro detection.** Detect the OS/version and use the right package names and
  service units.
- **systemd-native.** Install services as units, not background scripts.
- **No magic.** Every action is logged; the script is auditable.

## Phases

1. **Preflight** — check OS, version, privileges, and required ports; bail early
   with a clear message if unmet.
2. **Packages** — install PostgreSQL, NGINX, PHP-FPM, and (optionally) BIND/
   PowerDNS, Postfix, Dovecot via the distro package manager.
3. **Database** — create the `ghostcp` role and database; run migrations.
4. **Configuration** — write `/etc/ghostcp/` config from prompts/flags; generate
   strong secrets (`JWT_SECRET`, backup key) rather than shipping defaults.
5. **Binaries** — install the `ghostcp-api` binary (and UI assets) into place.
6. **systemd units** — install and enable the [units](systemd.md); start the API.
7. **Bootstrap admin** — create the initial admin account.
8. **Postflight** — health-check the running API and print next steps.

## Flags (intended)

| Flag | Purpose |
|------|---------|
| `--non-interactive` | use flags/env instead of prompts |
| `--with-dns` / `--with-mail` | install the optional service stacks |
| `--admin-user` / `--admin-password` | bootstrap admin credentials |
| `--port` | API listen port |

## Idempotency

Re-running should detect existing packages, database objects, config, and units
and update rather than duplicate them — the same convergence model GhostCP uses
for the resources it manages.
