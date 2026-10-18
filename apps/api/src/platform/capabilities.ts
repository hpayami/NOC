import type { CapabilityStatus } from '@noc/shared';

/**
 * Honest capability register. Every state is explicit: nothing here is "available" until its
 * integration, authorization controls and tests exist. Phase 0 ships only the management plane.
 */
export const CAPABILITIES: CapabilityStatus[] = [
  {
    id: 'auth.rbac',
    state: 'available',
    phase: 0,
    reason: 'Argon2id, short-lived JWT, rotating refresh tokens, permission-based RBAC',
  },
  {
    id: 'audit.tamper_evident',
    state: 'available',
    phase: 0,
    reason: 'Hash-chained audit trail with verification endpoint',
  },
  {
    id: 'asset.inventory',
    state: 'available',
    phase: 1,
    reason:
      'Observation ingestion with deterministic identity resolution; no automatic connectors yet',
  },
  {
    id: 'asset.discovery.passive',
    state: 'not_implemented',
    phase: 1,
    reason: 'Requires authorized scope and a passive observer',
  },
  {
    id: 'asset.discovery.active',
    state: 'available',
    phase: 1,
    reason:
      'Approval-gated TCP host/service discovery inside segments that allow it; two-person rule; dry-run default',
  },
  {
    id: 'noc.health_monitoring',
    state: 'degraded',
    phase: 1,
    reason:
      'TCP availability checks, collector heartbeats, maintenance windows, metrics and SNMPv3 snapshots via collectors; host agent pending',
  },
  {
    id: 'network.topology',
    state: 'available',
    phase: 1,
    reason:
      'Verified L2 adjacency from collector LLDP snapshots; observed-communication edges await flow sources',
  },
  {
    id: 'nids.suricata',
    state: 'not_configured',
    phase: 2,
    reason: 'No Suricata sensor registered; EVE ingestion not enabled',
  },
  { id: 'nsm.zeek', state: 'not_configured', phase: 2, reason: 'No Zeek sensor registered' },
  {
    id: 'events.pipeline',
    state: 'not_implemented',
    phase: 2,
    reason: 'Normalized envelope defined; ingestion pipeline not built',
  },
  {
    id: 'soc.alerts',
    state: 'not_implemented',
    phase: 2,
    reason: 'Schema present; no detections produce alerts yet',
  },
  {
    id: 'soc.incidents',
    state: 'not_implemented',
    phase: 3,
    reason: 'Lifecycle rules implemented and tested; API not yet exposed',
  },
  {
    id: 'response.actions',
    state: 'not_implemented',
    phase: 3,
    reason: 'Approval rules implemented and tested; execution integrations absent',
  },
  {
    id: 'nips.inline_prevention',
    state: 'disabled',
    phase: 4,
    reason: 'Never enabled automatically; requires Linux sensor, approval and rollback plan',
  },
  {
    id: 'assessment.engagements',
    state: 'not_implemented',
    phase: 5,
    reason: 'Scope enforcement implemented and tested; workers absent',
  },
  {
    id: 'ml.analytics',
    state: 'not_implemented',
    phase: 6,
    reason: 'Analysis service exposes health only; no models trained',
  },
];
