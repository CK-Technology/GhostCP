# Quick Start

Run a local GhostCP instance for development. This uses the `docker/` dev stack
(PostgreSQL + API) with host networking. It is **not** a production deployment.

## 1. Configure

```bash
cp .env.example .env
# edit secrets as needed
```

## 2. Start the dev stack

```bash
docker compose -f docker/compose.yml up
```

This brings up `postgres:16` and the API. Postgres is health-gated; the API
waits for it before starting and applies migrations on boot.

Because the stack uses **host networking**, services reach each other on
`localhost` — there are no published port mappings.

## 3. Verify

```bash
curl http://localhost:8080/health
```

Expected:

```json
{ "status": "healthy", "service": "ghostcp-api", "version": "0.1.0" }
```

## 4. Authenticate

Log in with the bootstrap admin (`ADMIN_USER` / `ADMIN_PASSWORD`):

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

The response contains a JWT. Send it as `Authorization: Bearer <token>` on
protected routes. See the [API reference](../api/README.md).

## Running without Docker

```bash
# point DATABASE_URL at a local PostgreSQL, then:
cargo run -p ghostcp-api
```

## Next steps

- [API reference](../api/README.md)
- [DNS](../dns/) and [authoritative interop](../dns/authoritative-interop.md)
- [Development workflow](../development/)
