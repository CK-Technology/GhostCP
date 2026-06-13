# Development

Working on GhostCP itself.

- [Docker](docker.md) — the dev/test stack
- [Building](building.md) — workspace builds, UI feature sets
- [Testing](testing.md) — tests, clippy, audit

See also the root [CONTRIBUTING.md](../../CONTRIBUTING.md) for the contribution
workflow and coding standards.

## Quick reference

```bash
# format
cargo fmt --all

# lint (error gate)
cargo clippy --workspace --all-targets -- -D warnings

# test
cargo test -p ghostcp-api

# audit
cargo audit
```
