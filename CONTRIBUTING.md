# Contributing to GhostCP

Thanks for your interest in GhostCP. It is an experimental Rust control panel
under active development, and contributions are welcome — from bug fixes to docs
to wiring up the scaffolded subsystems.

## Getting Started

### Prerequisites

- **Rust** (2024 edition; rustc 1.85+; project is developed on current stable)
- **PostgreSQL** 16
- **Docker** (optional, for the dev stack)
- For the UI: the `wasm32-unknown-unknown` target and
  [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos)

```bash
rustup target add wasm32-unknown-unknown
```

### Clone and build

```bash
git clone <repository-url>
cd GhostCP

cp .env.example .env

# Option A: dev stack (Postgres + API, host networking)
docker compose -f docker/compose.yml up

# Option B: run against a local Postgres
cargo run -p ghostcp-api
```

The project layout:

```
GhostCP/
├── api/          # Rust/Axum control plane (ghostcp-api)
│   └── src/
│       ├── handlers/   # HTTP route handlers
│       ├── drivers/    # DNS + ACME provider drivers
│       ├── system/     # host service integration
│       └── auth/        # JWT, Argon2, TOTP
├── ui/           # Leptos 0.8 web UI (ghostcp-ui)
├── templates/    # Tera templates for NGINX, PHP-FPM, Postfix, Dovecot
├── migrations/   # SQLx migrations (PostgreSQL is the source of truth)
├── docker/       # dev/test stack only
└── docs/         # documentation
```

## Development Workflow

Before opening a pull request, your change must pass the same gates CI runs.

### Format

```bash
cargo fmt --all
```

### Lint

Clippy is treated as an error gate — no warnings:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Test

```bash
cargo test -p ghostcp-api
```

### Build everything

```bash
cargo build --workspace

# UI under both feature sets
cargo build -p ghostcp-ui --features ssr
cargo build -p ghostcp-ui --no-default-features --features hydrate \
  --target wasm32-unknown-unknown
```

### Audit dependencies

If you add or bump dependencies:

```bash
cargo audit
```

It must exit clean. Any advisory that is intentionally ignored needs a written
justification in [`.cargo/audit.toml`](.cargo/audit.toml).

## Coding Standards

- **PostgreSQL is the source of truth.** Schema changes go through a new SQLx
  migration; keep queries reconciled with the schema.
- Keep changes focused. Don't refactor unrelated code or add speculative
  abstractions for hypothetical needs.
- Comments explain *why*, not *what*. Don't scatter version numbers through the
  code — versioning lives in [`CHANGELOG.md`](CHANGELOG.md).
- Validate at system boundaries (request input, external APIs); trust internal
  invariants.
- Documentation goes under `docs/`, organized by topic, lowercase-hyphenated
  filenames. Be accurate; mark planned vs implemented. No marketing fluff.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>

[body]
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.

Examples:

```
feat(dns): wire AXFR transfer to local BIND driver
fix(auth): reject expired TOTP backup codes
docs(websites): document WordPress multisite layout
```

## Pull Request Process

1. Fork and create a topic branch (`feat/...`, `fix/...`, `docs/...`).
2. Make your change; keep commits logically scoped.
3. Run fmt, clippy, test, and the builds above — all green.
4. Update `docs/` and `CHANGELOG.md` (Unreleased section) when behavior changes.
5. Open a PR describing **what** changed and **why**. Link related issues.
6. Address review feedback with new commits (don't force-push over review history
   unless asked).

## Areas to Contribute

The status table in the [README](README.md#status) shows what's implemented vs
scaffolded. High-value areas:

- **Web provisioning** — wire NGINX/PHP-FPM templates to the web-domain handlers
- **SSL/ACME** — complete the Let's Encrypt DNS-01/HTTP-01 flow
- **Mail** — Postfix/Dovecot provisioning from templates
- **DNS interop** — secondary transfer testing (BIND/PowerDNS/Technitium)
- **UI** — replace mock data with live API calls
- **Docs & tests** — always welcome

## Reporting Bugs & Security Issues

- Functional bugs: open a GitHub issue with reproduction steps.
- Security vulnerabilities: **do not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
