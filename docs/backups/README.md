# Backups

GhostCP models **backup configurations** describing what to back up and where.

## Backends

The default backend is selected by `DEFAULT_BACKUP_BACKEND` (default `local`).
Backups are encrypted with `BACKUP_ENCRYPTION_KEY`. See
[configuration](../getting-started/configuration.md). A Restic-style backend for
S3/MinIO-compatible object storage is the target for off-host backups.

## API

See the [backup routes](../api/README.md#backups):

```bash
# list backup configs
curl http://localhost:8080/api/v1/backups \
  -H 'Authorization: Bearer <token>'

# create a backup config
curl -X POST http://localhost:8080/api/v1/backups \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"nightly","backend":"local","schedule":"0 3 * * *"}'
```

## Scope

A backup config targets site files, databases, and/or mailboxes with a schedule
and retention policy. Scheduled execution runs through the
[jobs](../architecture/jobs.md) runtime.

## Status

Routes and schema exist; execution and restore flows are **scaffolded** — see the
[status table](../../README.md#status).
