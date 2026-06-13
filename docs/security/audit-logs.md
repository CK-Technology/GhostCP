# Audit Logs

GhostCP aims to record mutating actions (who changed what, and when) so that
administrative activity is reviewable.

## Intent

- Every state-changing operation (create/update/delete of users, domains, zones,
  certificates, …) should produce an audit entry.
- Entries capture the actor, action, target resource, and timestamp.

## Status

Audit logging is **planned**. The request flow runs through the API where actor
and action are known, which is the natural insertion point. This page documents
the intended model; see the [status table](../../README.md#status) for current
state.
