# Phase 2 — progress log

## Slice 1 — Suricata EVE ingestion, event pipeline, alert queue, SOC/NIDS pages (2026-10-18)

**Delivered**

- `packages/shared/src/engines/suricata.ts`: `normalizeEveRecord` — EVE JSON → normalized event
  envelope v1. Timestamp normalization (`+0000`, microseconds), category/type mapping, severity
  from Suricata levels, rule id `gid:sid:rev`, MITRE techniques from rule metadata, correlation
  ids (`flow:`, `community:`), **allow-listed engine fields only — `payload`, `payload_printable`
  and `packet` are never copied**. `stats`/`engine`/`packet` records are refused with a reason.
- `rules/alert-state.ts`: triage state machine (acknowledge → investigate → escalate/resolve/
  false-positive/suppress/reopen; dispositions and reopen require a note).
- `apps/api/src/events/pipeline.ts`: bounded batches (≤ 1000 records, 4 MiB), NDJSON or JSON
  array, per-record rejection reasons returned (nothing dropped silently), SHA-256 dedup
  (`security_events.dedup_hash`, insert-on-conflict-do-nothing), asset correlation by address in
  one query, alert upsert keyed by (sensor, rule, src, dst) with explainable priority
  (`computeAlertPriority`), per-sensor `last_event_at`, Prometheus counters
  (`noc_api_events_ingested_total`, `_duplicate_total`, `_rejected_total{reason}`,
  `noc_api_alerts_created_total{severity}`, `noc_api_ingest_lag_seconds{sensor}`).
- Routes: `POST /api/v1/ingest/suricata/eve` (sensor credential, or `events.ingest` + `?sensorId`
  for audited fixture replay; engine sensors only), `GET /api/v1/events` (≤ 7 days, keyset,
  filters), `GET /api/v1/events/stats`, `GET /api/v1/alerts` (+ `/:id` with contributing events),
  `PATCH /api/v1/alerts/:id` (state machine, audited, assignment, suppression expiry).
- Schema (`0004_phase2_events`): `alerts.rule_ref/source_sensor_id/src_ip/dst_ip/last_event_id`,
  `sensors.last_event_at`. RBAC: `events.ingest` (blue_team_engineer).
- Platform status: `nids.suricata` is now **dynamic** (not_configured → degraded → available based
  on registered sensors delivering events in the last 10 min); `events.ingest_lag_seconds` and
  `events.ingest_failures` are real metrics. `events.pipeline`, `soc.alerts` → available.
- Web: **SOC Alerts** (queue, open/all, quick triage with notes) and **NIDS Monitoring**
  (engine sensors with lag, events by type/severity, honest empty states).

**Verified**

Shared: 6 normalizer/state-machine tests. API: 4 integration tests — caller rules (sensor vs replay
vs refused; non-engine sensor 409), a mixed batch (duplicate, stats, malformed, dns, flow) with
counts, payload stripping, asset correlation, occurrence counting, detail/stats, idempotent resend;
bounds (1001 records → 413, 7-day range, RBAC); triage transitions + audit + fresh alert after
disposition. Totals: shared 83, API 69, web 4; e2e covers both pages.

**Not delivered in slice 1**

Zeek log adapter, detection-rule registry, SSE push, Sigma/host-event sources, retention
enforcement, the Suricata forwarder itself (sensor-side). See slice 2 below for what moved.

## Slice 2 — Zeek adapter, detection-rule registry, live alert stream (2026-10-18)

**Delivered**

- `packages/shared/src/engines/zeek.ts`: `normalizeZeekRecord` — Zeek JSON logs (`conn`, `dns`,
  `http`, `ssl`, `files`, `notice`, `weird`, `ssh`, …) → event envelope v1. The log path comes from
  the record's `_path` (JSON-streaming) or the request's `?path=`; timestamps accept epoch seconds
  or ISO. `notice` records become `detection` events (`ruleId = zeek:<note>`, severity from the
  note family), everything else is `network`/`protocol` telemetry. Correlation ids: `zeek:<uid>`
  and `community:<community_id>` so Zeek and Suricata records for the same flow join. Allow-listed
  engine fields only; file bodies and extracted content are never copied.
- `packages/shared/src/engines/suricata-rules.ts`: `parseSuricataRules` — Suricata/Snort rule
  syntax (`action proto src sp -> dst dp (options)`), commented-out rules are imported as
  `enabled: false`, `msg`/`sid`/`rev`/`classtype`/`metadata`/`reference` extracted, severity from
  `classtype` or `metadata.signature_severity`, ATT&CK technique ids from
  `metadata.mitre_technique_id`. Line-numbered parse errors are returned, never swallowed.
- `apps/api/src/rules/service.ts` + `routes/rules.ts` (`/api/v1/detection-rules`): import with a
  **mandatory licence and source**, idempotent by `(source, 1:sid)` with revision-aware update
  counts, list (keyset, filters, name/SID search), stats, `validate` and `lifecycle` transitions
  (`detection_rules.change`; audited). Alerts now carry `rule_id` → the registry row when the
  detection's `gid:sid` is known (`alerts.rule_id`, resolved per batch in the pipeline).
- `apps/api/src/events/bus.ts` + `GET /api/v1/alerts/stream`: in-process `AlertBus` publishing
  `created` / `updated` / `triaged` events over **SSE** (`alerts.read`, keepalive every 15 s,
  listener cap → `error` event instead of silent drop). The web shell proxies it at
  `/stream/alerts` (Bearer token stays server-side) and `LiveRefresh` re-renders the SOC queue
  on change with an honest live/offline indicator.
- `GET /api/v1/events/correlated?correlationId=` — all events sharing a correlation id (flow,
  community id, Zeek uid) across engines; backed by a GIN index on `correlation_ids`.
- `POST /api/v1/ingest/zeek/logs[?path=]` — same caller rules as the EVE endpoint; a non-Zeek
  sensor is refused with 409. Ingest body limit is configurable (`INGEST_BODY_LIMIT_BYTES`,
  default 4 MiB) and also applies to rule imports.
- Schema (`0005_phase2_zeek_rules`): `detection_rules.enabled/action/classtype/rule_set/content/
imported_by`, `security_events` correlation GIN index.
- Platform status: `nsm.zeek` is **dynamic** like `nids.suricata`; new `detection.rule_registry`
  capability. Web **Detection Engineering** page (stats, import form for `detection_rules.change`
  holders, searchable registry, empty state that says nothing is downloaded automatically).

**Verified**

Shared: 7 new tests (Zeek conn/notice/weird normalization, timestamp forms, path fallback,
rule parser incl. disabled rules, severity/technique extraction, error reporting). API: 3
integration tests — Zeek ingest (sensor-kind guard, notice → alert with title from `msg`,
correlation lookup across engines), rule registry (RBAC incl. SoD, licence required, idempotent
re-import, search, lifecycle, stats, alert `ruleId` linkage), SSE stream (`ready`, `created`,
`triaged` events through the real HTTP handler). Totals: shared 90, API 72, web 4, pytest 4;
e2e 3/3 (analyst now also visits Detection Engineering).

**Not delivered yet**

Zeek/Suricata forwarder binaries (sensor side), rule-set fetching from upstream (deliberately
manual: licence must be declared), Sigma/host-event sources, retention jobs, SSE for other
queues, cross-engine alert merging beyond shared correlation ids.

## Slice 3 — Rule deployment bundles with site targeting (2026-10-18)

**Delivered**

- **Deploy is a separate act.** `POST /api/v1/detection-rules/{id}/deploy` moves a _validated_
  rule to `deployed` and needs `detection_rules.deploy`, which the role catalogue keeps apart from
  `detection_rules.change` (SoD pair: the engineer who writes rules does not ship them). Draft
  rules cannot be deployed (409). Audited `detection_rules.deploy`.
- **Site targeting.** `PUT /api/v1/detection-rules/{id}/targets` sets the rule's site keys
  (validated against the sites catalogue; empty = every sensor of the engine). A targeted rule
  never reaches a sensor without a site. Audited `detection_rules.targets`.
- **Per-sensor bundles.** `GET /api/v1/agents/rules-bundle` (sensor credential) returns the
  deployed, enabled rules for that sensor's engine (Suricata: `et_open`/`custom`/`vendor`; Zeek:
  `zeek_script`) and site, in a stable order, with `bundleSha256` = SHA-256 of a canonical
  manifest (source, id, revision, content hash). `ETag`/`If-None-Match` → 304 so sensors can poll
  cheaply. Sensor kinds that consume no registry rules get 404, not an empty promise.
- **Acknowledgement and state.** Heartbeats carry `rulesBundleSha256`; the sensor record stores
  the acknowledged digest and time. `GET /api/v1/detection-rules/deployment` lists every enabled
  sensor inside the caller's site scope with the expected digest/rule count versus what the sensor
  acknowledged; `inSync` is true only for an exact match — a sensor that never acknowledged, or
  acknowledged another bundle, is out of sync. Disabling or retiring a rule changes the expected
  digest immediately.
- Pure rules in `packages/shared/src/rules/rule-bundle.ts` (`bundleEngineFor`, `ruleTargetsSite`,
  `selectBundleRules`, `bundleManifest`); the API only hashes.
- Web: deploy button (for `detection_rules.deploy` holders, validated rules only), target-site
  editor, and a deployment table (sensor, kind, site, expected rules, in/out of sync, acknowledged
  digest and time).
- Schema (`0016_phase2_rule_bundles`): `detection_rules.sites`, `sensors.rules_bundle_sha256`,
  `sensors.rules_bundle_applied_at`.

**Verified**

Shared: engine mapping, site targeting, selection (draft/disabled/no-content/other-engine/other-
site excluded, stable order), manifest sensitivity (revision and content change it, registry id
does not). API: two sites, two Suricata sensors and one Zeek sensor; empty identical bundles
before deployment; deploy refused for draft (409) and for the engineer (403); admin deploys;
unknown target 400; targeted rule reaches dc1 only; Zeek gets none; 304 on matching ETag; bogus
credential 401; heartbeat acknowledgement flips `inSync` for the right sensor only, a wrong
digest stays out of sync; disabling a rule desynchronises until re-fetch and re-ack; sensor
status exposes the digest; audit rows. Totals: shared 106, API 100, web 4, pytest 8; e2e 5/5.

**Not delivered**

A sensor-side agent that fetches and installs the bundle (the sensor contract is defined; the
reference agent is Phase 4/7 work), rule-level per-sensor status (state is per bundle), Sigma
compilation to engine rules.
