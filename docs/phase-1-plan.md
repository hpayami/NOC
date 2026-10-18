# Phase 1 — Asset inventory and NOC: implementation plan

Prerequisite: Phase 0 acceptance (see README) is green on `main`.

## Deliverables

1. **Observation ingestion** — `POST /api/v1/assets/observations` (permission `discovery.run_passive`
   for collectors with a sensor credential). Validates `AssetObservation`, persists, enqueues
   resolution.
2. **Identity resolution job** — deterministic correlation: agent id > cloud instance id > MAC set
   overlap > (hostname + segment) ; IP alone never merges. Writes `assets`, `asset_interfaces`,
   `conflicts_with`; keeps provenance and `data_confidence`.
3. **Passive discovery connectors** (default on, scope-gated): ARP/neighbor table reader for Linux
   hosts via SSH/agent, DHCP lease parser (ISC/Kea), DNS/PTR enrichment with per-segment budgets.
4. **SNMPv3 poller** (authPriv only; no v1/v2c): sysDescr/ifTable/ifXTable/entPhysical; interface
   counters into a metrics table with per-class intervals; host sensor tables where exposed.
5. **Host agent foundation** — signed enrollment, heartbeat, basic inventory (OS, CPU, RAM, disks,
   NICs, listening services). Linux first.
6. **Availability monitoring** — ICMP/TCP checks with dependency-aware suppression; distinguish
   `offline` from `unreachable_monitoring_path` using collector health.
7. **Network segments & topology** — segment CRUD, L2 adjacency from LLDP/CDP where SNMP exposes it
   (`verified`), observed communication edges (`inferred`), sensor-coverage edges.
8. **Coverage dashboard** — assets by `monitoringCoverage` and `assuranceState`; "unreachable /
   not fingerprinted" lists; per-segment gap view.
9. **Active discovery (approval-gated)** — ICMP sweep + approved TCP service checks only, with
   `discovery.approve_active` → `discovery.run_active` separation, concurrency/rate budgets,
   dry-run, cancellation, and `evaluateTarget` enforced in the worker.

## API additions

`/api/v1/assets`, `/assets/:id`, `/assets/:id/observations`, `/assets/:id/timeline`,
`/network/segments`, `/network/topology`, `/sensors` (collector registry), `/discovery/jobs`.

## Schema changes

`asset_metrics` (time-partitioned), `discovery_jobs`, `discovery_scopes` (reuses
`AuthorizedTargetScope`), `collector_credentials` (encrypted at rest, never returned), `maintenance_windows`.

## Tests

Identity-resolution property tests (no merge on shared IP; merge on MAC overlap; conflict recorded),
SNMP parser fixtures, DHCP lease fixtures, availability-vs-collector-outage distinction, scope
enforcement in the active-discovery worker (deny public, deny excluded, deny expired), coverage
dashboard numbers reconcile with table counts.

## Non-goals

No vulnerability scanning, no packet capture, no automatic remediation, no Internet-wide scanning.
