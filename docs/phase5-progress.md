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
findings carry no CVSS unless an integration supplies it; the discovery job worker still mints a
new asset per IP-only observation on re-runs (the assessment worker avoids this; the same reuse
should be applied to discovery); engagement reports/export; evidence store beyond run records.
