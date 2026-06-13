# Jobs

Provisioning actions (issuing a certificate, syncing a zone, creating a mailbox)
are modeled as **system jobs** so they can be tracked, retried, and audited
rather than run as opaque fire-and-forget calls.

## Model

- Job records are persisted in PostgreSQL (`api/src/models/job.rs`).
- The job runtime lives in `api/src/jobs.rs`.
- Jobs are exposed over the API at `/api/v1/jobs` (list / create) — see the
  [API reference](../api/README.md).

A job carries a type, a target resource, a status, and a result/error. Because
state is in the database, a job's lifecycle is observable and idempotent
provisioning can converge desired state.

## Status

The job model, table, and routes exist. Full orchestration (a worker that drains
queued jobs and applies provisioning steps transactionally) is staged alongside
the web/mail/SSL handlers. The DNS subsystem performs its actions directly today.
