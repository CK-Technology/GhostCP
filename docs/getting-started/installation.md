# Installation

## Prerequisites

- **Rust** — 2024 edition (rustc 1.85+; developed on current stable)
- **PostgreSQL** — version 16
- **Docker** — optional, for the dev/test stack
- For UI work: the WASM target and `cargo-leptos`

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos      # optional, for full UI builds
```

## Get the source

```bash
git clone <repository-url>
cd GhostCP
```

## Workspace layout

GhostCP is a Cargo workspace:

- `ghostcp-api` (`api/`) — the Axum control plane
- `ghostcp-ui` (`ui/`) — the Leptos web UI
- `ghostcp` (root) — workspace package

Build the API:

```bash
cargo build -p ghostcp-api
```

Build the UI (both feature sets):

```bash
cargo build -p ghostcp-ui --features ssr
cargo build -p ghostcp-ui --no-default-features --features hydrate \
  --target wasm32-unknown-unknown
```

## Next steps

- Set up your [configuration](configuration.md)
- Run the [quick start](quick-start.md)
