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
  {
    id: 'nsm.zeek',
    state: 'not_configured',
    phase: 2,
    reason: 'Zeek JSON log ingestion ready; no Zeek sensor registered',
  },
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
    state: 'available',
    phase: 3,
    reason:
      'Incident lifecycle with controlled deviations, append-only timeline, alert linkage, audited transitions; closing requires incidents.close',
  },
  {
    id: 'data.retention',
    state: 'available',
    phase: 3,
    reason:
      'Per-class retention policies with legal hold; bounded scheduled purge of events, metrics and observations; audit trail never purged',
  },
  {
    id: 'response.actions',
    state: 'available',
    phase: 3,
    reason:
      'Propose → approve (two-person, SoD, expiry) → execute → rollback, fully audited; in-platform executors: escalate, recommend_isolation, collect_evidence',
  },
  {
    id: 'response.enforcement_executors',
    state: 'not_configured',
    phase: 3,
    reason:
      'Endpoint isolation, indicator blocking, session disabling and rule deployment have no integration; such actions can be approved but execution is refused',
  },
  {
    id: 'nips.policy_plane',
    state: 'available',
    phase: 4,
    reason:
      'Inline policies: propose → two independent approvals → time-boxed enable by a non-approver on a healthy inline-capable sensor; kill switch; sensor acknowledges applied version',
  },
  {
    id: 'nips.inline_prevention',
    state: 'disabled',
    phase: 4,
    reason: 'No inline policy is enabled; sensors run detect-only (fail-open)',
  },
  {
    id: 'assessment.engagements',
    state: 'not_implemented',
    phase: 5,
    reason: 'Scope enforcement implemented and tested; workers absent',
  },
  {
    id: 'detection.rule_registry',
    state: 'available',
    phase: 2,
    reason:
      'Suricata rule import with licence, parsing, severity/ATT&CK extraction, validation lifecycle, alert linkage',
  },
  {
    id: 'ml.analytics',
    state: 'not_implemented',
    phase: 6,
    reason: 'Analysis service exposes health only; no models trained',
  },
];

/** Capabilities whose state depends on what is registered and reporting right now. */
type SensorState = Array<{ enabled: boolean; lastEventAt: Date | null }>;

export function resolveCapabilities(input: {
  suricataSensors: SensorState;
  zeekSensors?: SensorState;
  enabledIpsPolicies?: Array<{
    sensorName: string;
    mode: string;
    expiresAt: Date | null;
    applyState: string;
  }>;
  now: Date;
}): CapabilityStatus[] {
  const engines: Record<string, { sensors: SensorState; label: string }> = {
    'nids.suricata': { sensors: input.suricataSensors, label: 'Suricata' },
    'nsm.zeek': { sensors: input.zeekSensors ?? [], label: 'Zeek' },
  };
  return CAPABILITIES.map((cap) => {
    if (cap.id === 'nips.inline_prevention') {
      const on = input.enabledIpsPolicies ?? [];
      if (on.length === 0) return cap;
      const applied = on.filter((p) => p.applyState === 'applied').length;
      return {
        ...cap,
        state: applied === on.length ? 'available' : 'degraded',
        reason: `${on.length} inline policy(ies) enabled (${applied} acknowledged by sensors): ${on
          .map(
            (p) =>
              `${p.sensorName}:${p.mode}${p.expiresAt ? ` until ${p.expiresAt.toISOString()}` : ''}`,
          )
          .join(', ')}`,
      };
    }
    const engine = engines[cap.id];
    if (!engine) return cap;
    const enabled = engine.sensors.filter((s) => s.enabled);
    if (enabled.length === 0) return cap;
    const fresh = enabled.filter(
      (s) => s.lastEventAt && input.now.getTime() - s.lastEventAt.getTime() < 10 * 60_000,
    );
    if (fresh.length === enabled.length)
      return {
        ...cap,
        state: 'available',
        reason: `${fresh.length} ${engine.label} sensor(s) delivering events`,
      };
    return {
      ...cap,
      state: 'degraded',
      reason: `${fresh.length}/${enabled.length} ${engine.label} sensor(s) delivered events in the last 10 minutes`,
    };
  });
}
