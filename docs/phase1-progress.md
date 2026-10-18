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
