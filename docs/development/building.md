# Building

GhostCP is a Cargo workspace: `ghostcp-api` (`api/`), `ghostcp-ui` (`ui/`), and
the root `ghostcp` package.

## Whole workspace

```bash
cargo build --workspace
```

The UI crate defaults to the `ssr` feature so a bare workspace build succeeds.

## API

```bash
cargo build -p ghostcp-api
cargo run   -p ghostcp-api      # applies migrations on startup
```

## UI

The UI builds in two modes:

```bash
# server-side rendering (native)
cargo build -p ghostcp-ui --features ssr

# browser hydration (WASM)
cargo build -p ghostcp-ui --no-default-features --features hydrate \
  --target wasm32-unknown-unknown
```

Add the WASM target once if needed:

```bash
rustup target add wasm32-unknown-unknown
```

For a full SSR + hydration build with asset bundling, use
[`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos):

```bash
cargo leptos build
```

## Notes

- Leptos feature gating: `ssr` pulls in Axum/Tokio/reqwest; `hydrate` pulls in
  `gloo-net` and builds the WASM bundle.
- On `wasm32`, `uuid` uses its `js` feature for browser randomness (configured in
  `ui/Cargo.toml`).
