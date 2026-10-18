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

**Not delivered yet**

Zeek log adapter, detection-rule registry (`detection_rules` populated from rule sets with
licences), WebSocket/SSE push for the queue, Sigma/host-event sources, retention enforcement,
the Suricata forwarder itself (sensor-side).
