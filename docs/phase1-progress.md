# Phase 1 — progress log

Tracks delivered slices of `phase-1-plan.md`. Each entry lists what is verified and what is not.

## Slice 1 — observation ingestion, identity resolution, inventory API & page (2026-10-18)

**Delivered**

- `packages/shared/src/rules/identity.ts`: `resolveAssetIdentity` — tiered, deterministic
  (agent id 0.95 → cloud instance id 0.95 → MAC overlap 0.85 → hostname within the same segment
  0.6). IP addresses are never an identity. Multiple matches on one tier → `ambiguous`, nothing
  merged. `detectConflicts` records agent/cloud/MAC/hostname/segment disagreements.
- `apps/api/src/assets/service.ts`: ingestion under a transaction-scoped advisory lock; candidate
  lookup via array-overlap on linked observations; segment inference from `network_segments.cidr`
  (most specific wins); one interface row per MAC; fill-if-null for collector-reported hardware
  attributes (OS, model, serial, RAM…); provenance appended per observation (capped at 32);
  `data_confidence` = best tier seen; every ingest audited with the decision payload.
- Routes: `/api/v1/assets` (keyset cursor on `(last_seen_at, id)`, filters for segment/class/
  coverage/status/hostname search), `/assets/:id`, `/assets/:id/observations`, `/assets/:id/timeline`
  (observations + audit merged), `PATCH /assets/:id` (metadata only; identity fields rejected by
  schema), `/assets/coverage`; `/api/v1/network/segments` (GET, POST with new `network.manage`
  permission), `/api/v1/network/topology`.
- RBAC: `network.manage` (platform_admin, noc_operator); `assets.manage` added to noc_operator;
  `assets.read_sensitive` granted to security_admin (serial numbers hidden from everyone else).
- Web: Asset Inventory page (coverage and assurance tiles, table, honest empty state).
- Capability register: `asset.inventory` → `available` (API-fed observations only),
  `network.topology` → `degraded` (graph API exists, no relationship sources).

**Verified**

- Shared: 7 new identity tests (62 total). API: 10 new integration tests — RBAC on ingestion,
  create/match/no-IP-merge/agent-precedence-with-conflict/ambiguous, segment inference and
  hostname-in-segment matching, keyset pagination + filters + bad cursor, metadata patch RBAC and
  audit/timeline, topology with zero fabricated edges (46 total). Web unit 4, Playwright e2e covers
  the inventory page's empty state. Full gate (`scripts/verify.sh`) green.

**Not delivered yet (next slices)**

Passive discovery connectors (ARP/DHCP/DNS), SNMPv3 poller, host agent, availability monitoring
with collector-outage distinction, LLDP/flow-derived topology edges, approval-gated active
discovery, maintenance windows, asset metrics table.

## Slice 2 — availability monitoring, collectors, maintenance windows, metrics (2026-10-18)

**Delivered**

- `packages/shared/src/rules/availability.ts`: `classifyCheck` / `deriveOperationalStatus`
  (maintenance > positive up/down evidence > path loss; silent collector or stale results are
  `path_loss`, never `down`), `deriveSensorHealth`, `isWindowActive`; tested (8 tests).
- Schema (`0001_phase1_monitoring`): `monitoring_checks`, `check_results`, `maintenance_windows`,
  `asset_metrics`; enums `check_kind`, `check_outcome`.
- `apps/api/src/monitoring/service.ts`: `AvailabilityService.reevaluateAsset` (latest result per
  check via `DISTINCT ON`, collector heartbeat state, active windows by asset or segment; sets
  `monitoring_coverage = partial` when checks exist), `runTcpCheck` (connect-only, hard timeout),
  `MonitoringScheduler` (bounded concurrency, due-check selection, started from `server.ts`,
  configurable via `MONITORING_*`).
- Routes: `/api/v1/monitoring/checks` (create requires the target to be a known address of the
  asset and non-public), `/checks/:id/results` (collector reports; 409 for platform-run checks),
  `/maintenance-windows` (asset xor segment, ≤ 30 days), `/overview`; `/api/v1/assets/:id/metrics`
  (ingest ≤ 500 points, read ≤ 7 days / 5 000 points); `/api/v1/sensors` (register — inline mode
  rejected at registration), `/:id/status`, `/:id/health`, `/:id/heartbeat`.
- RBAC: `monitoring.read|manage|ingest` (noc_operator holds all three; read for analysts,
  responders, security/platform admins, auditors).
- Web: NOC Operations page (status tiles, sensors, active windows, recent results); status column
  on the inventory. Capability `noc.health_monitoring` → `degraded` (pollers pending).

**Verified**

API: 5 integration tests — RBAC + target rule, real TCP probe online→offline with interval
gating and `unsupported` for ICMP, collector heartbeat turning the same `down` evidence from
`unreachable_monitoring_path` into `offline`, maintenance override + overview, bounded metrics.
Totals: shared 70, API 51, web 4; e2e covers the NOC page.

**Not delivered yet**

SNMPv3 poller, host agent, passive discovery connectors, LLDP/flow topology edges, approval-gated
active discovery, threshold alerts/escalation (Phase 2 alert queue), retention enforcement jobs.

## Slice 3 — approval-gated active discovery, SNMPv3 snapshots, verified topology (2026-10-18)

**Delivered**

- `packages/shared/src/rules/discovery.ts`: `validateDiscoveryScope` (never public; every include
  range must lie inside a segment with `activeDiscoveryAllowed`; connect-level techniques only;
  ≤ 4096 targets, ≤ 16 concurrency, ≤ 50 rps; IPv6 ranges refused), `expandTargets`
  (host addresses only, exclusions, cap). 5 tests.
- Schema (`0002_phase1_discovery`): `discovery_jobs`, `discovery_job_targets`.
- `apps/api/src/discovery/service.ts`: request → decision → claim → run → finish. Two-person rule
  enforced in the service (requester can never approve; denial is audited and persists). The
  worker re-validates the scope policy and runs `evaluateTarget` per target _before_ any connect;
  dry-run (default) records decisions only; pacing via token gate; cancellation honoured between
  targets; reachable hosts become observations (`tcp_service_check`, open ports in attributes).
- Routes: `/api/v1/discovery/jobs` (list/create/detail), `/jobs/:id/decision`
  (`discovery.approve_active`), `/jobs/:id/run` (`discovery.run_active`, 202 + background),
  `/jobs/:id/cancel`.
- `apps/api/src/collectors/snmp.ts` + `POST /api/v1/collectors/snmp/snapshots`
  (`monitoring.ingest`): collectors push normalized SNMPv3 walks; the platform never speaks SNMP.
  Produces an observation (identity resolution), one interface per ifName with speed/admin/oper
  state, counters as `if.<ifIndex>.*` metrics + `sys.uptime_seconds`, and LLDP neighbours as
  **verified** `layer2_adjacency` edges when the neighbour resolves by chassis MAC or unique
  sysName; unresolved neighbours are counted, never invented.
- Web: Topology page (segments with their active-discovery policy, relationships with
  verified/inferred label and evidence). Capabilities: `asset.discovery.active` and
  `network.topology` → `available`; `noc.health_monitoring` stays `degraded` (host agent pending).

**Verified**

API: 6 discovery tests (policy rejections, two-person rule + state machine + audit, dry run with
exclusions, live loopback run creating an observation with the open port, run-time window denial,
cancellation) and 3 SNMP tests (RBAC/collector checks, interface + metric mapping with MAC-based
re-correlation, LLDP → verified edge with an unresolved neighbour). Totals: shared 75, API 60,
web 4; e2e covers the Topology page.

**Not delivered yet**

Host agent, passive ARP/DHCP/DNS connectors, flow-derived inferred edges, threshold alerting and
escalation (Phase 2 alert queue), discovery/maintenance UI forms (API-only today), retention jobs.

## Slice 4 — host-agent foundation, passive neighbour ingestion, sensors page (2026-10-18)

**Delivered**

- Sensor credentials: an operator mints a single-use, 24 h **enrolment token**
  (`POST /api/v1/sensors/:id/enrolment-token`, `sensors.manage`); the agent exchanges it once at
  `POST /api/v1/agents/enrol` for a long-lived credential (`<sensorId>.<secret>`, only its SHA-256
  stored; the token is burned; every attempt audited). Agent endpoints accept **only**
  `X-Sensor-Credential`; user JWTs are refused there and sensor credentials unlock nothing else.
- `POST /api/v1/agents/heartbeat | inventory | metrics | neighbors` with per-sensor rate limits.
  Inventory → observation anchored on the agent id (OS, arch, RAM, vendor/model, disks, boot time),
  interfaces per name (loopback dropped), **listening services** (`asset_services`, replaced per
  source with first-seen preserved), host asset linked to the sensor, coverage → `partial`.
- Passive discovery: ARP/NDP/DHCP neighbour batches from agents or collectors
  (`POST /api/v1/collectors/neighbors`, `monitoring.ingest`) → one observation each
  (`arp_neighbor` / `dhcp_lease`); loopback and MAC-less/hostname-less entries skipped.
  `packages/shared/src/parsers/neighbors.ts`: `parseIpNeigh`, `parseDhcpdLeases` for the agent.
- Schema (`0003_phase1_agents`): `asset_services`; `sensors.enrolment_token_hash/expires_at/enrolled_at`.
- Asset detail now returns `services`. Web **Sensors & collectors** page with one-time enrolment
  token issuance. Capabilities `asset.discovery.passive`, `noc.health_monitoring` → `available`.

**Verified**

API: 5 agent tests (token RBAC/single-use/audit outcomes, credential vs JWT separation, inventory
create + re-send with service replacement and first-seen retention, metrics gated on inventory,
neighbour batch with no IP-only merge + collector path). Shared: 2 parser tests. Totals: shared 77,
API 65, web 4; e2e covers the Sensors page.

**Phase 1 remaining**

Flow-derived inferred edges (needs the Phase 2 flow collector), threshold alerts/escalation
(Phase 2 alert queue), discovery/maintenance UI forms, retention jobs, the agent binary itself
(the API contract and parsers are in place; the collector process is a separate deliverable).
