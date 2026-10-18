import ipaddr from 'ipaddr.js';
import { IPS_HEARTBEAT_MAX_AGE_SECONDS, IPS_MAX_ENABLE_HOURS } from '../entities/ips';
import type { SensorHealthState } from '../enums';

export type IpsCheck = { ok: true } | { ok: false; code: string; message: string };

export interface IpsSensorState {
  enabled: boolean;
  inlineCapable: boolean;
  kind: string;
  lastHeartbeatAt: Date | null;
  latestHealthState: SensorHealthState | null;
}

const fail = (code: string, message: string): IpsCheck => ({ ok: false, code, message });

/** Conditions a sensor must satisfy to run inline — at enable time and for as long as it stays enabled. */
export function checkIpsSensor(s: IpsSensorState, now: Date): IpsCheck {
  if (s.kind !== 'suricata') return fail('sensor_kind', 'Only Suricata sensors can run inline');
  if (!s.enabled) return fail('sensor_disabled', 'Sensor is disabled');
  if (
    !s.lastHeartbeatAt ||
    (now.getTime() - s.lastHeartbeatAt.getTime()) / 1000 > IPS_HEARTBEAT_MAX_AGE_SECONDS
  )
    return fail('sensor_silent', `No heartbeat in the last ${IPS_HEARTBEAT_MAX_AGE_SECONDS} s`);
  if (!s.inlineCapable)
    return fail('not_inline_capable', 'Sensor has not reported inline capability');
  if (s.latestHealthState !== 'healthy')
    return fail(
      'sensor_unhealthy',
      `Sensor health is ${s.latestHealthState ?? 'unknown'}, not healthy`,
    );
  return { ok: true };
}

/**
 * Continuation gate: an enabled policy stays enabled only while the sensor still satisfies the
 * enable conditions. Any failure means the platform returns the sensor to detect-only itself —
 * a sensor that is silent or degraded while inline is the one state this platform never accepts.
 */
export function checkIpsContinuation(input: { sensor: IpsSensorState; now: Date }): IpsCheck {
  return checkIpsSensor(input.sensor, input.now);
}

/**
 * Gate for switching a sensor inline. Every condition is a hard refusal: the platform never
 * enables prevention on a sensor that is unhealthy, silent, not inline-capable, already running
 * another policy, or on a policy that lacks independent approvals.
 */
export function checkIpsEnable(input: {
  status: string;
  requiredApprovals: number;
  approverIds: readonly string[];
  enablerId: string;
  sensor: IpsSensorState & { hasEnabledPolicy: boolean };
  enabledForHours: number;
  now: Date;
}): IpsCheck {
  if (input.status !== 'approved')
    return fail('bad_state', `Policy is ${input.status}, not approved`);
  if (input.approverIds.length < input.requiredApprovals)
    return fail(
      'insufficient_approvals',
      `${input.approverIds.length}/${input.requiredApprovals} approvals`,
    );
  if (input.approverIds.includes(input.enablerId))
    return fail('sod', 'An approver may not enable the policy they approved');
  if (input.enabledForHours < 1 || input.enabledForHours > IPS_MAX_ENABLE_HOURS)
    return fail('ttl', `enabledForHours must be 1..${IPS_MAX_ENABLE_HOURS}`);
  const s = input.sensor;
  const gate = checkIpsSensor(s, input.now);
  if (!gate.ok) return gate;
  if (s.hasEnabledPolicy)
    return fail('policy_conflict', 'Another policy is already enabled on this sensor');
  return { ok: true };
}

/** Protected ranges must be non-public: inline drops are scoped to networks the operator owns. */
export function publicCidrs(cidrs: readonly string[]): string[] {
  return cidrs.filter((c) => {
    try {
      const [addr] = ipaddr.parseCIDR(c);
      const a =
        addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()
          ? (addr as ipaddr.IPv6).toIPv4Address()
          : addr;
      return ![
        'private',
        'loopback',
        'linkLocal',
        'uniqueLocal',
        'carrierGradeNat',
        'unspecified',
      ].includes(a.range());
    } catch {
      return true; // unparseable == public (fail closed)
    }
  });
}
