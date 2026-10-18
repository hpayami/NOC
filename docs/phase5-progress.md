# Phase 5 — progress log

## Slice 1 — Authorised assessment engagements, workers, findings (2026-10-18)

**Invariant kept:** nothing active runs without written authorisation, a versioned scope that is
currently approved, an open window, and a per-target scope decision taken inside the worker
immediately before each connection (`evaluateTarget`: exclusions win, public refused).

**Delivered**

- `packages/shared/src/entities/assessments.ts`: engagement contract (authorisation reference,
  objective, scope, stop conditions, emergency contact, evidence retention), scope update with
  reason, decision/transition requests, `EngagementRecord` (approvals per scope version), runs
  (`CreateRunRequest` defaults to dry run), per-target records, technique catalogue, findings
  list/update contracts, `FindingRecord`.
- `packages/shared/src/rules/assessment.ts`: `validateEngagementTransition` (draft →
  pending_approval → approved → active → paused/completed; cancel/complete/pause need a reason;
  closed states are final), `RISKY_SERVICES` / `findingForOpenPort` (observed-exposure findings
  for FTP, Telnet, SMB, RDP, VNC, databases, Redis, Elasticsearch, Memcached, MongoDB — observed,
  never exploited).
- `apps/api/src/assessments/service.ts` + `routes/assessments.ts` (`/api/v1/assessments`,
  `/api/v1/findings`):
  - **Engagements**: create (`assessments.plan`; window must be open-ended in the future, scope
    non-empty) → submit → approve/reject (`assessments.approve`; the responsible operator or
    creator can never approve — audited as denied) → activate (`assessments.execute`; only when
    `approvedScopeVersion == scopeVersion` and the window has started) → pause / complete /
    cancel. A **scope change** stores a new version and sends an approved/active engagement back
    to pending approval; runs are refused until the new version is approved. **Window expiry**
    is enforced lazily on every read: the engagement becomes `expired` and queued runs are
    cancelled (audited as `system:assessments`).
  - **Runs**: technique must be in the authorised scope _and_ executable in this build
    (`host_discovery`, `service_fingerprint`; the other seven report why not). The in-platform
    worker additionally obeys the segment discovery posture (`validateDiscoveryScope`): private
    targets inside segments that allow active discovery, bounded concurrency/rate. Targets are
    enumerated at creation; execution is synchronous, dry-run by default, paced by a rate gate,
    cancellable between targets, and every target records its decision, reasons and outcome.
  - **Findings**: an open risky port on a reachable host becomes a validated finding on the
    asset (unique per asset + title); re-observation updates `lastDetectedAt` and evidence and
    never touches the triage status. Triage (`findings.manage`) records status and note, audited.
    The worker reuses the single asset that already owns the target IP instead of minting a new
    one per run (an IP alone is never an identity).
- Schema (`0009_phase5_assessments`): `assessment_runs`, `assessment_run_targets`,
  engagement columns (objective, created_by, scope_version, approved_scope_version, timestamps,
  close_reason), `approvals.subject_version`, finding columns (description, last_note,
  updated_at) and the asset+title uniqueness.
- Capabilities: `assessment.engagements` → available; `assessment.workers` → degraded with the
  executable/non-executable split spelled out.
- Web **Red Team** (engagement list with scope/window/run/finding counts, capability state, new
  engagement form, detail page with scope, approvals, transitions by permission, run queueing and
  execution, findings) and **Vulnerability Management** (open/all findings, observed marker,
  triage form for `findings.manage`).

**Verified**

Shared: 3 tests (lifecycle incl. reasons and finality, executable techniques, port → finding
mapping). API: 2 integration tests — authorisation/validation, submit, self-approval refused,
reject → draft, approve, approver cannot activate, activate, scope change invalidates approval
and blocks runs, re-approval, completion reason, finality, audit outcomes; technique catalogue,
not-in-scope and no-worker refusals, RBAC, dry run (decisions only, nothing sent), live run
against a loopback listener on a risky port (reachable, finding created, inventory observation),
re-run updates instead of duplicating, triage by analyst survives re-observation, worker policy
refuses a target outside a discovery-allowed segment (422), window expiry → expired + queued run
cancelled. Totals: shared 98, API 84, web 4, pytest 4; e2e 5/5 (red-team operator drafts an
engagement through the UI, submits it, sees no run form and no self-approval, findings page
honest).

**Known limitations / not delivered**

External scanners (vulnerability, TLS, web, dependency) and detection validation have no worker;
findings carry no CVSS unless an integration supplies it; engagement reports/export; evidence
store beyond run records. (The per-run asset minting for IP-only observations was closed in
Phase 7: address-only observations re-attach to the sole holder of the address.)

## Slice 2 — Engagement reports (2026-10-18)

**Delivered**

- `GET /api/v1/assessments/engagements/{id}/report` (`assessments.read`; `?format=markdown` for
  a shareable rendering). The report is built only from the platform's own records: engagement
  and authorisation, scope (version, approval state, window), every run, **per-technique
  status** (`performed` / `dry_run_only` / `not_performed` / `not_executable`), **per-address
  coverage** for every enumerated in-scope address (`assessed_with_findings`,
  `assessed_no_findings`, `unreachable`, `denied`, `not_assessed`), addresses probed under an
  older scope version kept and flagged, findings, and a `limitations` array that is part of the
  contract. Limitations are generated from the same records (techniques without an executor or
  without a live run, addresses never probed, run-time denials, non-answers, scope changed after
  the last live run, unapproved scope, unvalidated findings, interim status) and are rendered
  **before** the findings in Markdown. Findings appear only for holders of `findings.read` and
  only inside the requester's site scope; otherwise the report states they are withheld. Every
  export is audited (`assessments.report`).
- Pure rules in `packages/shared/src/rules/assessment-report.ts` (`techniqueCoverage`,
  `targetCoverage`, `reportLimitations`, `renderEngagementReportMarkdown`) so the web app, the
  API and tests share one definition of "assessed".
- Web: **Download report (Markdown)** on the engagement page through a BFF route that forwards
  the session's token; the API decides authorization and content.

**Verified**

Shared: technique status from live runs only; per-address classification including dry-run rows
ignored, denial reasons kept, out-of-scope probes flagged; limitation sentences; Markdown order
(limitations before findings), finding and target rows, withheld rendering. API: report after
four runs — coverage 1/1 with findings, open ports and technique recorded, findings included for
`findings.read`, Markdown content type and reference line, withheld for a blue-team engineer,
404 for an unknown engagement, three audited exports. Totals: shared 102, API 98, web 4,
pytest 8; e2e 5/5.

**Not delivered**

PDF/DOCX export, evidence attachments in the report, per-finding remediation guidance beyond
the finding record, and signed/hashed report artefacts (the audit row records the export, not a
digest of its content).

## Slice 3 — Vulnerability catalogue and CVE enrichment (2026-10-18)

**Delivered**

- `vulnerability_catalog` imported by the operator from the feeds they already trust:
  `POST /api/v1/vulnerabilities/import` (`threat_intel.manage`) accepts **NVD API 2.0** responses
  (primary CVSS v4/v3.1/v3.0/v2 metric, English description, CWE ids, dates), the **CISA KEV**
  catalogue (exploited-in-the-wild flag with added/due dates, never a CVSS score) and a native
  array. Parsers are pure (`packages/shared/src/rules/vuln-feeds.ts`); malformed entries are
  reported, not dropped silently; a document with nothing parseable is rejected (422). Imports
  **merge by CVE**: a feed overwrites only the fields it carries, so KEV never clears a score and
  NVD never clears the exploited flag; `sources` records which feeds contributed. Re-imports are
  idempotent (`unchanged`). Audited `vulnerabilities.import`.
- **Enrichment by CVE id only.** Findings that reference a catalogued CVE and have no CVSS get
  the catalogue's score/vector filled in (never overwritten); every finding now carries
  `vulnerabilities[]` with the matching catalogue entries. There is no product/version matching —
  the platform does not claim a host is vulnerable because of a package name.
- Reads (`findings.read`): `GET /api/v1/vulnerabilities` (search, `knownExploited` filter;
  exploited and highest CVSS first), `GET /{cveId}`, `GET /stats` including the CVEs findings
  reference that the catalogue lacks — what to import next.
- Risk: `assessAssetRisk` adds to the score and to the basis for open findings whose CVE is known
  exploited or carries CVSS ≥ 9.0; the asset graph nodes and the risk profile use it.
- Capability `vuln.catalog`: `not_configured` until an import, then `available` with counts and
  the last import time, stating that enrichment is by CVE id only.
- Web: catalogue panel and import form (format + JSON paste) on the vulnerability page; CVSS and
  a KEV badge on findings there and in the asset-graph panel.
- Schema (`0017_phase5_vuln_catalog`): `vulnerability_catalog`.

**Verified**

Shared: NVD primary-metric selection, English description, CWE filtering, malformed id error,
missing metrics → nulls; KEV flag and dates without CVSS; native format, invalid JSON, wrong
shapes, last duplicate wins; risk amplification sentences. API: finding with one catalogued and
one unknown CVE; capability `not_configured` and `uncatalogued` listing; analyst cannot import;
NVD import enriches the finding; re-import unchanged; KEV merge keeps CVSS and sets the flag with
sources; 404/400 on lookups; filters; rejected feed; finding carries CVSS, vector and attached
record while the unknown CVE stays listed; risk profile and graph node basis mention exploitation
in the wild and CVSS ≥ 9; capability `available` with counts; three audit rows. Totals: shared 113,
API 102, web 4, pytest 8 + 7; e2e 5/5.

**Not delivered**

Automatic feed download (the operator imports from a trusted copy), product/version-based
matching (CPE), EPSS scores.

## Slice 4 — Reports workspace: period posture report (2026-10-18)

**Delivered**

- **Contract** (`packages/shared/src/entities/reports.ts`): `PostureReport` with twelve
  sections — assets, sensors, events, alerts, incidents, response actions, inline prevention,
  authorised assessments, findings/vulnerabilities, threat intelligence, advisory analytics,
  governance/audit — each carrying `state` (`available` / `withheld` / `not_configured` /
  `unavailable`), the permission that governs it, a note and `data` only when available; the
  period, the site scope the report was reduced to, and a limitations list. `ReportPeriodQuery`
  bounds the period to 1–365 days.
- **Rules** (`rules/posture-report.ts`, pure): `durationStats` (mean/median, null on empty),
  `humanDuration`, and a deterministic Markdown renderer that prints every section's state
  before any figure, so "withheld" or "not configured" is never read as zero activity.
- **Service** (`ReportService.posture`): bounded aggregate queries per plane, each behind the
  plane's own read permission and reduced by the reader's site scope through the existing
  predicates (assets, sensors, events, alerts, incidents, response actions, findings, ML
  results, threat-intel matches by attributed asset; IPS policies through their sensor's site).
  Engagements, runs and the audit trail are platform-wide and say so. Alerts report opened,
  closed, false positives and open-at-end but state that acknowledgement time is **not
  tracked** rather than estimating an MTTA; incidents report mean and median opened→closed for
  those closed in the period. Analytics distinguishes "withheld" from "unavailable" (service
  down and nothing stored). Governance includes denied/failed audit outcomes, logins and the
  hash-chain verification result. Every generation is audited (`reports.posture`) with the
  sections withheld.
- API `GET /api/v1/reports/posture?days=&format=json|markdown` (`platform.status.read`; the
  sections do their own gating). Web `/reports`: 7/30/90-day selector, limitations, one card
  per section with its state badge and the governing permission when withheld, Markdown
  download through the BFF. NAV marks the workspace implemented.

**Verified**

Shared (2): duration statistics never invent values; the renderer prints state lines for
withheld / not configured / unavailable sections, figures for available ones, no
`undefined`/`NaN`, deterministic output. API (1, through the real pipeline): an analyst on an
empty platform gets `not_configured` for the planes they can read and `withheld` for IPS,
assessments and ML; `days` out of range is 400; after three detections (one tuple repeated),
one indicator hit, one closed and one open incident the analyst's report counts 3 events from
1 sensor, 3 alerts opened with the indicator's severity, 2 incidents (1 closed, mean = median),
1 threat-intel match by type; the admin's report withholds alerts but reports sensors, assets
not configured, and governance with the chain verified and the logins counted; Markdown carries
the same figures and the withheld line; generation is audited. Totals: shared 127, API 110
(27 files), web 4, pytest 8 + agent 7; e2e 5/5 (analyst sees governance withheld, incidents
available).

**Known limitations**

No scheduled or stored reports (each call recomputes; the audit trail records who generated
what); no per-site breakdown inside a report (one scope per report); the audit-chain check runs
over the whole trail on every generation by an `audit.read` reader; alert acknowledgement time
remains untracked by design until alerts carry status timestamps.

## Slice 5 — Pentest workspace: methodology tracking per engagement (2026-10-18)

**Delivered**

- **Catalogue** (`packages/shared/src/rules/pentest.ts`, `PENTEST_METHODOLOGY`, code not data):
  sixteen non-destructive steps across seven PTES-aligned phases — pre-engagement
  (authorisation, scope confirmed, rules of engagement, NOC/SOC notified), reconnaissance
  (passive discovery, exposure review), enumeration (host discovery, service fingerprinting),
  vulnerability analysis (version identification, configuration review), verification
  (evidence without exploitation, false-positive review), post-engagement (stop conditions and
  deviations, nothing left behind), reporting (report delivered, remediation tracked). Steps
  mapped to a platform technique require evidence; exploitation, privilege escalation,
  persistence, lateral movement and denial of service are neither performed nor tracked.
- **Rules** (pure): `pentestWorkAllowed` (only approved/active/paused/completed engagements may
  progress non-pre-engagement steps), `checkItemUpdate` (`done` on an evidence step needs a
  run or finding; `blocked` and `not_applicable` need a note; resetting is always allowed),
  `pentestProgress` (completion over applicable steps, per phase).
- **Store** (`0020_phase5_pentest_methodology`, `pentest_items`): only the state an operator
  set — status, note, run and finding references, who and when — unique per (engagement, key).
  Plans materialise from the catalogue on read, so every engagement has one.
- **Service** (`PentestService`): plan with engagement context (status, scope versions, window,
  allowed techniques), whether work may proceed and why not, executable flag per technique
  (worker present here); `updateItem` verifies that referenced runs and findings belong to
  **this** engagement (404 otherwise), applies the rules (409 with the reason), and audits
  success and denial (`pentest.item_update`); `summaries` for the list.
- API `/api/v1/pentest`: `GET /methodology`, `GET /plans?engagementIds=`,
  `GET /engagements/{id}/plan` (`assessments.read`); `PUT /engagements/{id}/plan/{key}`
  (`assessments.execute`).
- Web `/pentest` (engagements with completion, blocked count, last update) and `/pentest/[id]`
  (plan by phase with status/technique/evidence badges, work-allowed banner with the reason,
  per-step form for status, note, run and finding references; read-only note otherwise). All
  19 workspaces are now implemented; the honest placeholder page keeps no routes.

**Verified**

Shared (3): catalogue validity, unique keys, every phase represented, no destructive wording,
technique steps require evidence; approval gating per phase, evidence and note rules,
resets allowed; progress arithmetic over applicable steps and per phase. API (1): methodology
visible to a read-only auditor, not to the platform admin; plan on a draft with all steps
not started, work blocked with the reason, executable flags (host discovery yes, vulnerability
scan no worker, documentary null); auditor and approver 403 on update, unknown step 404,
pre-engagement step done on a draft, enumeration refused before approval with the reason,
`blocked` without note refused; after two-person approval and activation, `done` without
evidence refused, in-progress accepted, a run of another engagement refused as evidence
(404), the engagement's own dry run accepted, `not_applicable` with reason accepted; progress
and per-phase counts; summaries for several ids ignoring garbage; audit shows 4 successes
and the denials. Totals: shared 133, API 112 (29 files), web 5, pytest 8 + agent 7; e2e 5/5
(red-team operator records a pre-engagement step and is refused on enumeration while pending).

**Known limitations**

Steps are operator assertions with evidence links, not automated verification; the catalogue
is fixed (no per-organisation methodology yet); evidence selection lists runs and findings of
the engagement only (by design) and the UI uses plain multi-selects.
