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
    id: 'auth.sso',
    state: 'not_configured',
    phase: 7,
    reason:
      'OIDC (authorization code + PKCE) available; set OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_REDIRECT_URI to enable',
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
    state: 'available',
    phase: 5,
    reason:
      'Authorisation-first engagements with versioned scope, independent approval, window enforcement and per-target scope checks inside the worker',
  },
  {
    id: 'assessment.workers',
    state: 'degraded',
    phase: 5,
    reason:
      'In-platform workers: host_discovery and service_fingerprint (TCP connect, observed-exposure findings); vulnerability/TLS/web/dependency scanners and detection validation need external integrations',
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
    state: 'not_configured',
    phase: 6,
    reason: 'Analysis service not reachable; advisory baseline scoring unavailable',
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
  ml?: { reachable: boolean; models: number; results: number; detail: string | null };
  sso?: { enabled: boolean; issuer: string | null; jit: boolean };
  now: Date;
}): CapabilityStatus[] {
  const engines: Record<string, { sensors: SensorState; label: string }> = {
    'nids.suricata': { sensors: input.suricataSensors, label: 'Suricata' },
    'nsm.zeek': { sensors: input.zeekSensors ?? [], label: 'Zeek' },
  };
  return CAPABILITIES.map((cap) => {
    if (cap.id === 'auth.sso') {
      if (!input.sso?.enabled) return cap;
      return {
        ...cap,
        state: 'available',
        reason: `OIDC login against ${input.sso.issuer} (PKCE, RS256 ID tokens verified locally, JIT provisioning ${input.sso.jit ? 'on' : 'off'}, no e-mail auto-link unless enabled)`,
      };
    }
    if (cap.id === 'ml.analytics') {
      const ml = input.ml;
      if (!ml) return cap;
      if (!ml.reachable)
        return {
          ...cap,
          reason: `Analysis service not reachable (${ml.detail ?? 'no detail'}); results stored so far: ${ml.results}`,
        };
      return {
        ...cap,
        state: ml.models > 0 ? 'available' : 'degraded',
        reason: `Advisory only — ${ml.models} statistical model(s) registered, ${ml.results} stored result(s); nothing acts on scores automatically`,
      };
    }
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
