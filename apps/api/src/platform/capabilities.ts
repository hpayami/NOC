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
    state: 'available',
    phase: 1,
    reason:
      'ARP/NDP/DHCP neighbour batches pushed by enrolled agents and collectors; no in-platform sniffing',
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
    state: 'available',
    phase: 1,
    reason:
      'TCP checks, collector heartbeats, maintenance windows, metrics, SNMPv3 snapshots and enrolled host agents (inventory, services, metrics)',
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
    reason: 'EVE JSON ingestion ready; no Suricata sensor registered',
  },
  { id: 'nsm.zeek', state: 'not_configured', phase: 2, reason: 'No Zeek sensor registered' },
  {
    id: 'events.pipeline',
    state: 'available',
    phase: 2,
    reason:
      'Normalized envelope v1, dedup, asset correlation, bounded batches, rejection reporting, lag metrics',
  },
  {
    id: 'soc.alerts',
    state: 'available',
    phase: 2,
    reason: 'Alert queue from Suricata detections with explainable priority and audited triage',
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

/** Capabilities whose state depends on what is registered and reporting right now. */
export function resolveCapabilities(input: {
  suricataSensors: Array<{ enabled: boolean; lastEventAt: Date | null }>;
  now: Date;
}): CapabilityStatus[] {
  return CAPABILITIES.map((cap) => {
    if (cap.id !== 'nids.suricata') return cap;
    const enabled = input.suricataSensors.filter((s) => s.enabled);
    if (enabled.length === 0) return cap;
    const fresh = enabled.filter(
      (s) => s.lastEventAt && input.now.getTime() - s.lastEventAt.getTime() < 10 * 60_000,
    );
    if (fresh.length === enabled.length)
      return {
        ...cap,
        state: 'available',
        reason: `${fresh.length} Suricata sensor(s) delivering events`,
      };
    return {
      ...cap,
      state: 'degraded',
      reason: `${fresh.length}/${enabled.length} Suricata sensor(s) delivered events in the last 10 minutes`,
    };
  });
}
