# Docker (development)

The `docker/` directory provides a **development and test** stack only.
Production is a [host install](../deployment/). The stack uses **host
networking** so the API, PostgreSQL, and host services all share `localhost` —
this avoids the DNS/connectivity friction of bridge networking.

## Layout

```
docker/
├── Dockerfile              # dev image (Rust + cargo-watch)
├── compose.yml            # postgres:16 + api, host networking
└── scripts/
    └── wait-for-postgres.sh
```

## Usage

```bash
cp .env.example .env
docker compose -f docker/compose.yml up
```

This starts:

- **postgres** — `postgres:16`, health-gated.
- **api** — built from `docker/Dockerfile`, waits for Postgres, then runs under
  `cargo watch` so changes to `api/src` rebuild automatically.

Because of host networking there are no port mappings; reach the API on
`localhost:<PORT>` (default 8080):

```bash
curl http://localhost:8080/health
```

## Notes

- `DATABASE_URL` points at `localhost` (host networking), not a service name.
- The `api/`, `ui/`, and `templates/` directories are bind-mounted for live
  iteration; the Cargo target dir is a named volume to keep rebuilds fast.
- Tear down with `docker compose -f docker/compose.yml down` (add `-v` to drop the
  Postgres volume).
