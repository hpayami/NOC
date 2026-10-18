# Phase 3 — progress log

## Slice 1 — Incident management, IR workspace, retention enforcement (2026-10-18)

**Delivered**

- `packages/shared/src/entities/incidents.ts`: incident contracts — create (with alerts to
  attach), transition (`to` + optional reason), notes, update (assignee/commander/severity/
  title/summary), link/unlink alerts, list query, stats, timeline entry kinds and
  `IncidentDetail` (incident + attached alerts + append-only timeline + `allowedNext`).
- `apps/api/src/incidents/service.ts` + `routes/incidents.ts` (`/api/v1/incidents`): every
  mutation runs in one transaction under a row lock, appends a timeline entry and an audit
  event. The lifecycle rules from Phase 0 (`validateIncidentTransition`) are enforced: forward
  chain by default, deviations (early closure, reopen, type-specific skips) require a reason of
  ≥ 10 characters, closing/reopening requires `incidents.close` (SOC analysts hold
  `incidents.manage` only; responders hold both). A denied closure is audited as `denied`
  outside the transaction so the row survives the rollback. Closed incidents are read-only until
  reopened. Attaching an open alert escalates it through the alert state machine and publishes on
  the alert bus; an alert can belong to one incident at a time (409 otherwise); the alert's
  latest event is tagged with the incident id so retention keeps it as evidence.
- Stats: totals, by status/severity, closed in 30 days, mean time to close.
- `apps/api/src/retention/service.ts` + `routes/retention.ts` (`/api/v1/retention`): policies per
  data class (seeded defaults; `retention.read` to view, `retention.modify` to change — audited
  with before/after), audit floor of 365 days enforced, `legalHold` suspends purging. Enforcement
  maps classes to real stores (`security_events` keeps incident-tagged rows; `metrics` →
  `check_results`, `asset_metrics`, `sensor_health`; `observations` → `asset_observations`),
  reports `protected` for the audit trail and `dataset_absent` for classes with no store yet
  (raw events, flows, evidence, pcap) instead of pretending. Deletes run in bounded batches and
  report `truncated` when more remains; the hourly scheduler (`RETENTION_ENABLED`,
  `RETENTION_INTERVAL_MINUTES`) and `POST /api/v1/retention/run` share one service so the last
  report is visible in `GET /api/v1/retention`. Runs that delete something are audited.
- Schema (`0006_phase3_incidents_retention`): `incidents.opened_by`, `observations` retention
  class. Capabilities: `soc.incidents` and `data.retention` → available.
- Web: **Incident Response** workspace (stats tiles, create form, open/all list with cursor
  paging) and incident detail (timeline with deviation markers, notes, status transitions limited
  to `allowedNext` and hiding _closed_ without `incidents.close`, assign-to-me, attached
  alerts). **SOC Alerts** gained a one-click "open incident" per alert and links to the owning
  incident. Submit-button name/value is not carried reliably into server-action `FormData`, so
  the triage and transition controls set a hidden field synchronously on click.

**Verified**

API: 5 integration tests — create from alerts (escalation, one-owner rule, detach/attach,
audit actions), full standard flow with denied/required-reason/reopen cases and timeline
deviation count, notes/assignment/severity/filters/pagination; retention defaults, audit floor
and read/modify separation, purge keeping incident evidence, legal hold, bounded batches
(harness uses batch size 2 × 3). Totals: shared 90, API 77, web 4, pytest 4; e2e 3/3 — the
analyst flow now creates an incident through the UI, adds a note, moves it to triage and
confirms no close button is offered.

**Not delivered yet**

Response actions (propose → approve → execute with rollback; rules exist, no API), evidence
store, incident reports/export, SLA timers, user directory lookups for assignee display
(ids are shown), retention for stores that do not exist yet.
