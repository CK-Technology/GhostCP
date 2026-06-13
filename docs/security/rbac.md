# Role-Based Access Control

GhostCP uses a role model to gate privileged operations.

## Roles

| Role | Capability |
|------|-----------|
| **Admin** | Full access to all resources and users |
| **User** | Access scoped to their own resources |

The role is stored on the user record and carried in the session. The UI's
`AuthGuard` and the API's `auth_middleware` both consult it: an admin passes any
role check, while a non-admin must match the specific role a route requires.

## Enforcement

- The API gates protected routes behind `auth_middleware` (valid JWT required).
- Role checks distinguish admin from user for privileged actions.

## Status

The role enum and the guard/middleware checks exist. Fine-grained per-resource
authorization (e.g. resellers, ownership scoping on every endpoint) is minimal
today and is being expanded as the resource managers are wired. See the
[status table](../../README.md#status).
