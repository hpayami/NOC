# Architecture

## Planes and service boundaries

```
┌─────────────────────────────── Management plane ───────────────────────────────┐
│  apps/web (Next.js 15, RTL)  ──BFF/cookies──▶  apps/api (Hono, Drizzle, Zod)   │
│                                                   │ PostgreSQL (transactional) │
│                                                   │ Redis (rate-limit/cache)*  │
└───────────────────────────────────────────────────┼────────────────────────────┘
                                                    │ OpenAPI / authenticated WS*
┌──── Data collection plane* ────┐  ┌──── Detection & analysis plane* ────┐  ┌── Assessment plane* ──┐
│ Suricata EVE / Zeek adapters   │  │ normalization · correlation         │  │ engagement + scope    │
│ SNMPv3 / syslog / flow / agent │─▶│ event store adapter (PG → CH/OS)    │  │ isolated workers      │
│ sensor health & lag            │  │ services/analysis (FastAPI, ML adv.)│  │ scope check in worker │
└────────────────────────────────┘  └─────────────────────────────────────┘  └───────────────────────┘
                                             ┌── Response plane* ──┐
                                             │ approvals · rollback│
                                             │ expiring actions    │
                                             └─────────────────────┘
* = later phase; Phase 0 ships the management plane and the analysis service skeleton.
```

Boundaries are enforced in code, not only in diagrams:

- `packages/shared` holds the contract: strict Zod schemas, enums, the RBAC catalog, and pure
  domain rules (incident state machine, scope evaluation, assurance derivation, approval checks,
  priority). Both API and web import it; the DB enums are generated from it so nothing drifts.
- Engine adapters (Phase 2) consume engine output and emit `NormalizedEvent` v1. Business logic
  never sees Suricata/Zeek structures; engine-specific fields ride in the bounded `engine` bag.
- The event store is an interface. PostgreSQL `security_events` is the Phase 0/1 implementation
  for low-volume metadata; ClickHouse/OpenSearch slot in behind the same interface when volume
  requires it. Incident/alert APIs never query the event backend directly.
- Scope enforcement (`evaluateTarget`) is a pure function invoked inside the execution worker.
  UI checks are a convenience; the worker check is the control.

## Phase 0 request path

1. Browser → Next.js server component/action. Tokens live in httpOnly cookies on the web origin
   (`noc_access` 15 min; `noc_refresh` path-scoped to `/auth`).
2. Web → API with `Authorization: Bearer <access>`. The JWT carries only `sub`, `roles`, `tv`
   (token version) — **no permissions**. The API loads the live principal (status, roles →
   permissions) from PostgreSQL per request; a bumped `token_version` kills every token instantly.
3. Every sensitive route declares `requirePermission(...)`. There is no role-name check anywhere.
4. State-changing handlers run in a transaction that also appends to the hash-chained
   `audit_events` table under an advisory lock; the audit write and the change commit together.

## Data model notes

- Assets are resolved from `asset_observations`; IP addresses are observation attributes, never
  identity. Observations keep provenance and `conflicts_with`.
- `topology_relationships.verification` is `inferred` or `verified`; observed communication is
  never shown as cabling.
- `assurance_state` is derived, with visibility gaps outranking "no alerts"
  (`deriveAssuranceStates` in shared).
- `response_actions` distinguish `recommended` (changed nothing) from `executed`, carry
  `required_approvals`, `expires_at`, `rollback_plan`, `verification_result`.
- `retention_policies`, `monitoring` and `security_events` indices follow the query patterns in
  `apps/api/src/db/schema/*.ts` (time + source, asset + time, open-alert partial unique index).

## Observability

- `X-Request-Id` on every response; structured pino logs with the id, user and latency.
- `/metrics` (Prometheus) guarded by JWT permission or a static scrape token.
- `/ready` reflects database reachability; `/api/v1/platform/status` reports capability states,
  metric sources and `demoData: false`.

## What is deliberately absent in Phase 0

Discovery connectors, engine adapters, the event pipeline, alert/incident APIs, response execution,
assessment workers, ML models, WebSocket push. Each has schema and rules in place and is reported as
`not_implemented`, `not_configured` or `disabled` — never as a working feature.
