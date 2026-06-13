# Architecture

How GhostCP is structured and why.

- [Overview](overview.md) — components and data flow
- [Templating](templating.md) — how native service config is generated
- [Jobs](jobs.md) — background and orchestration work

## Principles

- **API-first.** The HTTP API is the contract; the UI is a client.
- **PostgreSQL is the source of truth.** Desired state lives in the database;
  service config is rendered from it.
- **Host-level, not orchestrated.** GhostCP manages one server's native services
  via templates + systemd, like HestiaCP — not a container scheduler.
- **Standards over proprietary glue.** DNS interoperates via AXFR/IXFR, NOTIFY,
  and TSIG rather than a bespoke replication protocol.
