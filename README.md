# NOC — Cyber Defense & Network Operations Platform

Unified NIDS/NIPS, NOC, SOC, Blue/Red Team and authorized assessment platform.
**Current state: Phase 0 (foundation).** The management plane, identity/RBAC, tamper-evident audit,
shared contracts and database schema exist and are tested. Packet capture, detection engines,
alerting, incidents, response and assessment are **not operational** and the platform says so at
`/api/v1/platform/status`.

Persian-first RTL UI with English localization; dark operational theme.

## Repository layout

```
apps/api            Hono + Drizzle + Zod API (OpenAPI at /api/v1/openapi.json)
apps/web            Next.js 15 (App Router, Server Components, BFF session)
packages/shared     Zod schemas, enums, RBAC catalog, pure domain rules (+ tests)
services/analysis   FastAPI analysis/ML service (Phase 0: health + honest status only)
infra/              docker-compose.yml (postgres, redis, app profile), sensor deployment notes
scripts/            start.sh · stop.sh · smoke.sh · env-report.sh
docs/               environment report, architecture, security model, deployment profiles, Phase 1 plan
```

## Prerequisites

Node 22+, pnpm 10 (`corepack enable`), Python 3.11+, PostgreSQL 16 (Docker or native), Redis 7
(optional in Phase 0).

## Quick start

```bash
cp .env.example .env            # set POSTGRES_PASSWORD, AUTH_JWT_SECRET (openssl rand -hex 32), ANALYSIS_INTERNAL_TOKEN
pnpm install
(cd services/analysis && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]')

./scripts/start.sh              # Docker: starts postgres+redis, migrates, runs api/web/analysis
#   or, with your own PostgreSQL at DATABASE_URL:
./scripts/start.sh --native-db

# first run only — create the administrator from env (refuses if any user exists)
BOOTSTRAP_ADMIN_EMAIL=you@example.com BOOTSTRAP_ADMIN_PASSWORD='<≥14 chars>' pnpm --filter @noc/api bootstrap-admin

open http://localhost:3000       # login → Command Center
./scripts/stop.sh               # stops processes; keeps all data volumes
```

`scripts/stop.sh` never removes volumes or databases. To wipe local data you must run
`docker compose -f infra/docker-compose.yml down -v` yourself.

## Verification

```bash
pnpm typecheck && pnpm lint && pnpm format:check
TEST_DATABASE_URL=postgres://noc:<pw>@127.0.0.1:5432/noc_test pnpm test   # shared unit + API integration + web unit
pnpm build
(cd services/analysis && .venv/bin/pytest -q)
SMOKE_EMAIL=... SMOKE_PASSWORD=... ./scripts/smoke.sh                       # against a running stack
E2E_EMAIL=... E2E_PASSWORD=... pnpm --filter @noc/web e2e                   # Playwright browser e2e (needs a running stack)
./scripts/verify.sh                                                         # the full CI gate locally
```

Recorded Phase 0 results: `docs/phase0-verification.md`.

## Phase 1 progress (asset inventory slice)

- `POST /api/v1/assets/observations` (permission `discovery.run_passive`) stores collector
  observations and resolves them with the deterministic identity rule in `packages/shared`
  (agent id → cloud id → MAC overlap → hostname-in-segment; **IP alone never merges**; ties are
  reported as ambiguous and left unlinked, conflicts are retained).
- `GET /api/v1/assets` (keyset pagination, filters), `/assets/:id`, `/assets/:id/observations`,
  `/assets/:id/timeline`, `PATCH /assets/:id` (metadata only, audited), `/assets/coverage`.
- `GET|POST /api/v1/network/segments` (CIDR → segment inference for observations),
  `GET /api/v1/network/topology` (nodes + edges with `inferred|verified` labels; no edge sources yet).
- Web **Asset Inventory** page with coverage/assurance tiles. No discovery connectors exist yet;
  `asset.inventory` is `available` for API-fed observations only, `network.topology` is `degraded`.
- **Availability monitoring** (`/api/v1/monitoring/*`): TCP checks executed in-process by the API
  (targets must be addresses the inventory attributes to the asset; public addresses refused),
  collector-run checks reporting results, maintenance windows, per-asset metrics
  (`/assets/:id/metrics`, 7-day bounded reads), sensor/collector registry with heartbeats
  (`/api/v1/sensors/*`). Operational status is derived from evidence: a silent collector yields
  `unreachable_monitoring_path`, never `offline`. ICMP/HTTP checks are stored as `unsupported`
  until an executor exists. Web **NOC Operations** page.
- **Approval-gated active discovery** (`/api/v1/discovery/jobs`): request (`discovery.run_active`)
  → approve by a _different_ person (`discovery.approve_active`) → run. Scope policy: never
  public, only inside segments that allow active discovery, bounded size/rate, connect-level
  techniques; dry-run by default; the worker re-checks every target before connecting.
- **SNMPv3 via collectors** (`/api/v1/collectors/snmp/snapshots`): interfaces, counters → metrics,
  LLDP neighbours → **verified** topology edges. Web **Topology** page.
- **Host agents** (`/api/v1/agents/*`): operator-issued single-use enrolment token → one-time agent
  credential (`X-Sensor-Credential`, hash-stored, separate from user auth) → heartbeat, inventory
  (interfaces, listening services, hardware/OS), metrics, passive ARP/NDP/DHCP neighbours. Web
  **Sensors & collectors** page. The agent binary is not part of this repository yet; the contract
  and `ip neigh` / `dhcpd.leases` parsers are.

## Phase 2 progress (NIDS and SOC alert queue)

- `POST /api/v1/ingest/suricata/eve`: Suricata EVE JSON (NDJSON or array, ≤ 1000 records) from an
  enrolled sensor — or audited fixture replay by `events.ingest` holders — is normalized to the
  v1 event envelope **without payloads**, deduplicated, correlated to assets and turned into an
  alert queue with explainable priority. Rejections are reported per record, never dropped.
- `GET /api/v1/events` (bounded), `/events/stats`, `/alerts` with audited triage (`PATCH`).
- Web **SOC Alerts** and **NIDS Monitoring** pages. `nids.suricata` capability is dynamic:
  it is `available` only while registered sensors deliver events.
- `POST /api/v1/ingest/zeek/logs[?path=]`: Zeek JSON logs normalized into the same envelope;
  notices become detections, flows share correlation ids with Suricata (`community_id`, uid).
  `GET /api/v1/events/correlated?correlationId=` joins them. `nsm.zeek` is dynamic too.
- `/api/v1/detection-rules`: Suricata rule import with a **declared licence and source**
  (idempotent, revision-aware, disabled rules kept as disabled), validation lifecycle, and
  alert → rule linkage. Nothing is fetched from upstream automatically.
- `GET /api/v1/alerts/stream`: SSE push of alert create/update/triage; the web shell proxies it
  so the SOC queue refreshes live. Web **Detection Engineering** page.

## Phase 3 progress (SOC incident response)

- `/api/v1/incidents`: lifecycle new → triage → investigation → containment → eradication →
  recovery → closed with controlled deviations (reason required), closing gated by
  `incidents.close`, append-only timeline, alert attachment (open alerts are escalated), stats.
  Every change is audited; a denied closure is audited too.
- `/api/v1/retention`: per-class retention policies with legal hold and a 365-day audit floor;
  bounded scheduled purge of events, metrics and observations. The audit trail is never purged;
  classes without a store report `dataset_absent` rather than a fake success.
- Web **Incident Response** workspace (list, create, detail with timeline/notes/transitions) and
  one-click incident creation from the SOC alert queue.
- `/api/v1/response-actions`: propose → approve (two-person for high-impact kinds, proposer may
  not approve, approver may not execute, expiry) → execute → roll back, fully audited. Only
  platform-owned executors exist (`escalate`, `recommend_isolation`, `collect_evidence`);
  network/endpoint/identity enforcement kinds can be approved but execution is refused until a
  verified integration exists — `GET /executors` reports exactly that. See
  `docs/phase3-progress.md`.

## Phase 4 progress (NIPS policy plane)

- `/api/v1/ips/policies`: inline-prevention policies as proposals — two independent approvals,
  enable only by a non-approver on a healthy, heartbeating, inline-capable Suricata sensor, with
  a 1–72 h TTL and a rollback plan; kill switch for either side of the approval split. Protected
  ranges must be private; rules must be validated. Expiry returns the sensor to detect-only.
- Sensors fetch `GET /api/v1/agents/ips-directive` (fail-open by contract) and acknowledge the
  applied version; `nips.inline_prevention` is reported from enabled **and acknowledged**
  policies only. Web **NIPS Policies** page. See `docs/phase4-progress.md`.

## Phase 5 progress (authorised assessments)

- `/api/v1/assessments`: engagements with an authorisation reference, versioned scope, independent
  approval (never the operator), activation only inside the authorised window, and automatic
  expiry. Runs are dry-run by default, limited to connect-level techniques the platform can
  actually execute, and re-check scope per target inside the worker. `/api/v1/findings`:
  observed-exposure findings with triage that survives re-observation.
- Web **Red Team** and **Vulnerability Management** pages. See `docs/phase5-progress.md`.

## Phase 6 progress (advisory ML)

- Analysis service: `robust-baseline` (median/MAD over a subject's own history) with explanations;
  short history is refused, not guessed; the model register says plainly that no labelled
  evaluation exists. `/api/v1/ml`: features from the platform's own event store, stored advisory
  results, batch scoring with reported skips. Nothing acts on a score automatically — the test
  suite asserts it. Web **ML Analytics** page. See `docs/phase6-progress.md`.

## What Phase 0 provides

- **Shared contracts** for every domain entity (users, assets, observations, segments, topology,
  sensors, events v1, alerts, incidents, findings, engagements, scopes, rules, indicators,
  actions, approvals, audit, retention, ML results) with strict validation and tests proving no
  public schema carries credential-like fields.
- **Domain rules** (tested): incident lifecycle with controlled deviations, deny-by-default scope
  evaluation (exclusions win, public refused, IPv4-mapped IPv6 normalized), assurance-state
  derivation where visibility gaps outrank "no alerts", explainable alert priority, approval checks
  with separation of duties and two-person rule for isolation/inline prevention.
- **PostgreSQL schema** — 25 tables, enums mirrored from shared, indexes for the stated query
  patterns, one reviewed migration.
- **API** — Argon2id, short-lived JWT + rotating refresh tokens with reuse detection, lockout,
  permission-based RBAC loaded live from the DB, hash-chained audit with verification, request
  correlation, structured logs, rate limits, body limits, CORS allow-list, Prometheus metrics,
  OpenAPI 3.1, honest capability/metric status.
- **Web** — RTL Persian shell with all 19 workspaces in navigation (non-Phase-0 ones show real
  capability state, never sample data), login, Command Center, Administration (users/roles), Audit
  Logs with chain verification, BFF cookie session with silent rotation.
- **Analysis service** — FastAPI skeleton with health/readiness and an advisory-only status.
- **Ops** — Compose stack with hardened containers, start/stop that preserve data, smoke test,
  CI (typecheck, lint, format, tests with PostgreSQL service, builds, pytest).

## Limitations (read before deploying)

- No sensor, discovery, detection, alerting, incident, response, assessment or ML functionality is
  active. Every such capability is reported as `not_implemented`, `not_configured` or `disabled`.
- Rate limiting is per API instance (in-memory). Add the Redis limiter before scaling out.
- JWT uses a shared HS256 secret; move to asymmetric keys when a second verifier appears.
- No MFA yet (extension point present). No multi-tenancy columns yet.
- Docker images and Compose were authored but could not be executed in the authoring environment
  (no Docker daemon) — see `docs/environment-report.md`. CI builds them.
- This host cannot capture packets meaningfully (no mirror port). Sensors require Linux hosts with
  authorized TAP/SPAN access — see `infra/sensor/README.md`.

## Roadmap

Phase 1 asset inventory & NOC → Phase 2 NIDS & event pipeline → Phase 3 SOC & IR → Phase 4 NIPS (policy plane delivered) → Phase 5 assessments (engagements + connect-level workers delivered) → Phase 6 ML (advisory baseline delivered) &
controlled response → Phase 5 authorized assessment → Phase 6 analytics → Phase 7 enterprise
readiness. Details: `docs/phase-1-plan.md`, `docs/architecture.md`.

All active security operations are limited to explicitly authorized assets and approved scopes.
