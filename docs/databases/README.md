# Databases

GhostCP manages application databases as a hosting resource, alongside web and
mail. (This is distinct from the control-plane's own PostgreSQL, which is the
system-of-record.)

## API

See the [database routes](../api/README.md#databases):

```bash
# list
curl http://localhost:8080/api/v1/databases \
  -H 'Authorization: Bearer <token>'

# create
curl -X POST http://localhost:8080/api/v1/databases \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"app_db","engine":"postgres"}'
```

## Model

A database record captures the engine, database name, and owning user. The intent
is least-privilege per-app databases and users (MySQL/MariaDB and PostgreSQL).

## Status

Routes and schema exist; provisioning against a live database server is
**scaffolded** — see the [status table](../../README.md#status).
