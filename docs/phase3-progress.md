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

## Slice 2 — Response actions: propose → approve → execute → roll back (2026-10-18)

**Delivered**

- `packages/shared/src/entities/response.ts`: proposal contract (kind, target, mandatory
  justification and rollback plan, bounded parameters, expiry 1–168 h), decision and execution
  requests, `ResponseActionRecord` (approvals, result, `executorAvailable`), executor catalogue.
- `apps/api/src/response/service.ts` + `routes/response.ts` (`/api/v1/response-actions`):
  - **Propose** (`response.propose`; `ips.propose` for inline prevention) validates the target
    (IP syntax, asset/rule existence, incident open) and never changes anything. Required
    approvals come from the Phase 0 rules (`requiredApprovals`): 0 for advisory kinds, 2 for
    endpoint isolation and inline prevention, 1 otherwise; advisory kinds start `approved`.
  - **Approve / reject** (`response.approve`) runs `checkApproval`: not the proposer, no
    duplicate approver, not expired, correct permission; approval counts are per distinct user.
    Refusals are audited outside the transaction.
  - **Execute** (`response.execute`) requires `approved`, not expired, executor ≠ any approver
    (user-level SoD on top of the role-level pair), and an executor for the kind. The claim and
    the execution are two transactions so a failing executor leaves the action `failed` with the
    error recorded. Verification result is stored (`passed` / `failed` / `not_run`).
  - **Roll back** (`response.rollback`) runs the executor's rollback and stores its output.
  - Executors in this build — honestly limited to what the platform itself owns: `escalate`
    (raises the linked incident to ≥ high, reversible), `recommend_isolation` (timeline record,
    advisory), `collect_evidence` (event ids + SHA-256 of the canonical envelope for the target,
    last 7 days, ≤ 200). `isolate_endpoint`, `block_indicator`, `disable_session`,
    `update_detection_rule`, `enable_inline_prevention` have **no executor**: they can be
    approved but execution is refused with the reason, and `GET /executors` says so.
  - Every step writes the incident timeline (`response_action` kind) and the audit trail.
- Schema (`0007_phase3_response_actions`): `response_actions.justification`, `parameters`.
  Capabilities: `response.actions` → available; `response.enforcement_executors` →
  not_configured.
- Web: response-action panel on the incident page — list with approvals, status, "no executor"
  marker, propose form (kinds show required approvals and executor availability), approve/
  reject with rationale, execute and roll back — each shown only with the matching permission.

**Verified**

API: 3 integration tests — executor catalogue + proposal validation (RBAC, rollback plan, IP,
missing asset, incident-bound kinds, `ips.propose` gate); workflow with one- and two-person
approvals, duplicate/self rules, rejection, execution refusal for a kind without executor
(action stays approved) and audit outcomes; in-platform execution with evidence hashes,
escalation + rollback restoring severity, approver≠executor refusal, lazy expiry, list filters.
Totals: shared 90, API 80, web 4, pytest 4; e2e 3/3 — the analyst proposes `collect_evidence`
on the incident page, sees it `approved` with no execute button (no `response.execute`).

**Not delivered yet**

Enforcement integrations (EDR/NAC, firewall, DNS-RPZ, IdP), sensor rule deployment, inline
prevention (Phase 4; never auto-enabled), evidence store beyond hashed references, user
directory lookups for approver display.

## Slice 3 — Threat intelligence: indicators and matching (2026-10-18)

**Delivered**

- **Feeds** (`packages/shared/src/rules/threat-intel.ts`, pure): platform JSON
  (`{ indicators: [...] }`), CSV with a header (`type,value` required; severity, confidence,
  tags, expires_at, description, source optional; `#` comments; real line numbers in errors) and
  **STIX 2.1** bundles (indicator objects with a single-comparison pattern on `ipv4-addr`,
  `ipv6-addr`, `domain-name`, `url` or `file:hashes`; compound patterns and non-STIX pattern
  types are refused explicitly rather than half-interpreted; `valid_until`, `confidence`,
  `labels`, `revoked` and the creating identity's name are kept). Values are canonicalised per
  type (ipaddr normal form, lower-cased domains without trailing dot, scheme-less URLs,
  lower-case hashes) so one indicator has one identity. A feed that states no severity or
  confidence leaves what another feed asserted untouched; the last occurrence inside one feed
  wins, so a revocation after an assertion holds.
- **Store** (`0019_phase3_threat_intel`): `threat_indicators` unique on (type, value) with
  source, confidence 0–100, severity, tags, expiry, revoked flag, match counters;
  `threat_indicator_matches` unique on (indicator, event, field) linking the event, the alert it
  raised or bumped, the asset and the sensor. Absence from a later feed never revokes; only an
  explicit `revoked` or `POST /indicators/{id}/revoke` does, and both are audited.
- **Matching** (`ThreatIntelService`): the event pipeline hands every accepted batch to an
  in-memory index (exact sets for addresses, hashes and URLs; domains match themselves and
  every subdomain; CIDRs by containment; 30 s refresh, invalidated on import/revoke). Observables
  are only what the normalisers keep: src/dst IP, DNS query, TLS SNI, HTTP host and host+URL,
  file SHA-256/SHA-1/MD5 — never payload. A hit records one match row and raises one SOC alert
  per (indicator, src, dst) with the indicator's severity and confidence through the normal
  priority formula; repeats bump the open alert, the same event never counts twice, and the
  `IngestReport` now carries `indicatorMatches`. On import the new or changed indicators are
  also compared with the last 24 h of stored events (bounded to 5 000), so "seen yesterday" is
  reported immediately (`retroMatches`).
- API `/api/v1/threat-intel`: `GET /stats`, `GET /indicators` (filters, inactive on request),
  `GET /matches` (site-restricted users see matches attributed to their assets only) under
  `threat_intel.read`; `POST /indicators/import`, `POST /indicators/{id}/revoke` under
  `threat_intel.manage`. Capability `threat_intel.indicators`: `not_configured` until an
  active indicator exists, then `available` with counts, sources and 24 h matches.
- Web `/threat-intel` is now a real workspace: state summary (or an honest "no indicator
  imported; events are not compared"), recent matches with a link to the alert, indicator table
  with type/text filters and inactive toggle, import form and revoke for `threat_intel.manage`.

**Verified**

Shared (6): normalisation per type, platform JSON with de-dup and error lines, CSV quoting and
real line numbers, STIX patterns (escaped quotes, hash keys, compound/foreign refused),
observable extraction, matching (exact, subdomain, CIDR v4/v6, once per indicator and field,
no suffix match on a bare label). API (3): import RBAC (analyst 403, operator 403 on read),
422 on an unparseable feed, merge semantics across two feeds (updated vs unchanged, confidence
not clobbered, tags unioned), list filters, stats by type and source, capability reason, audit;
inline matching of a five-event EVE batch (subdomain DNS, exact IP, CIDR, URL) → 4 matches,
4 alerts with the right severity/confidence, duplicate batch → nothing, a new sighting bumps
the open alert; events stored before the feed arrives are matched retroactively (2), an
unchanged re-import re-reads nothing, revocation stops matching and is reflected in list,
stats and the explicit-revoke feed path. Totals: shared 125, API 109 (26 files), web 4,
pytest 8 + agent 7; e2e 5/5 (analyst sees the workspace with no indicators and no import).

**Known limitations**

No scheduled feed fetching (imports are pushed through the API/UI); URL matching needs the
HTTP host and path the engine logged (no TLS-only URL inference); IPv6 CIDR indicators match
only IPv6 observables; retroactive matching covers 24 h / 5 000 events; indicator expiry is
enforced at match time, not by a purge.
