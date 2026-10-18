# Security model (Phase 0)

## Threat model summary

| Threat                              | Control                                                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential stuffing / brute force   | Argon2id (m=64 MiB, t=3), per-IP token-bucket on `/login`, account lockout after N failures, constant-time path for unknown users, identical error messages                     |
| Stolen access token                 | 15-minute TTL, HS256 with ≥32-byte secret, `token_version` check on every request (logout-all, role/status change, password change all bump it)                                 |
| Stolen refresh token                | Opaque 256-bit value stored as SHA-256; rotation on every use; replay of a rotated token revokes the whole family and is audited                                                |
| CSRF on cookie endpoints            | Refresh cookie `SameSite=Strict`, path-scoped to `/api/v1/auth`; Origin/Referer must be in the CORS allow-list; all other API calls are Bearer-only                             |
| Privilege escalation                | Permission-based RBAC, deny-by-default; separation-of-duties pairs are unit-tested so no built-in role can both approve and execute; users cannot change their own roles/status |
| Audit tampering                     | Hash chain over canonical JSON + previous hash; serialized via advisory lock; `/audit/verify` detects edits, deletions and reordering                                           |
| Secret leakage in responses         | Public schemas are `strictObject`; a test walks every public schema for credential-like keys; pino redacts auth headers, cookies, passwords                                     |
| Oversized / malformed input         | 256 KiB body limit (413), Zod validation on params/query/body (400), bounded strings and arrays everywhere                                                                      |
| Misconfiguration in production      | `loadEnv` refuses placeholder secrets, insecure cookies and `http://` origins when `NODE_ENV=production`                                                                        |
| Metrics exposure                    | `/metrics` requires `platform.metrics.read` or a static scrape token compared in constant time                                                                                  |
| Container escape / lateral movement | Compose services: non-root, `cap_drop: ALL`, read-only FS, `no-new-privileges`, loopback-only port bindings                                                                     |

## Not yet implemented (tracked)

- MFA (extension point: `users.mfa_enrolled`, `Approval` flows will require it for high-impact actions).
- Redis-backed distributed rate limiting (interface is in place; single-instance limiter today).
- WebSocket authorization (no WS endpoints exist yet).
- Asymmetric JWT signing (switch to EdDSA/JWKS when more than one verifier exists).
- Row-level tenant isolation (schema has no tenant column yet; add before multi-tenancy).

## Operational rules enforced by design

- Inline prevention (`sensors.mode = inline_prevention`) and `enable_inline_prevention` actions
  require two independent approvers (`requiredApprovals`) and can never be set by a sensor itself.
- ML results are typed `advisory: true`; nothing in the schema can represent an ML-triggered block.
- Assessment targets are checked by `evaluateTarget` with exclusions first, window and technique
  checks, IPv4-mapped IPv6 normalization, and a default refusal of publicly routable addresses.
