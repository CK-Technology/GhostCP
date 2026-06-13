# Testing

The checks below are the gates a change must pass before merge — the same ones
CI runs.

## Format

```bash
cargo fmt --all --check
```

## Lint

Clippy is an error gate; no warnings allowed:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

## Unit & integration tests

```bash
cargo test -p ghostcp-api
```

Integration tests live under `api/tests/`. Some exercise the router with
`axum-test`.

## UI builds

Treat both UI builds as part of testing, since feature gating can break one
without the other:

```bash
cargo build -p ghostcp-ui --features ssr
cargo build -p ghostcp-ui --no-default-features --features hydrate \
  --target wasm32-unknown-unknown
```

## Dependency audit

```bash
cargo audit
```

Must exit clean. Intentionally-ignored advisories carry written justification in
[`.cargo/audit.toml`](../../.cargo/audit.toml).

## Database-backed tests

Tests or queries that touch PostgreSQL expect a reachable database
(`DATABASE_URL`). The [dev Docker stack](docker.md) provides one; migrations apply
on startup.
