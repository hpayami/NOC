import { describe, expect, it } from 'vitest';
import {
  IPS_MAX_ENABLE_HOURS,
  ProposeIpsPolicyRequest,
  SensorIpsDirective,
  checkIpsEnable,
  publicCidrs,
} from '../src';

const now = new Date('2026-10-18T12:00:00Z');
const base = {
  status: 'approved',
  requiredApprovals: 2,
  approverIds: ['a1', 'a2'],
  enablerId: 'e1',
  sensor: {
    enabled: true,
    inlineCapable: true,
    kind: 'suricata',
    lastHeartbeatAt: new Date('2026-10-18T11:59:00Z'),
    latestHealthState: 'healthy' as const,
    hasEnabledPolicy: false,
  },
  enabledForHours: 24,
  now,
};

describe('inline prevention enable gate', () => {
  it('passes only when every safety condition holds', () => {
    expect(checkIpsEnable(base)).toEqual({ ok: true });
  });
  it('refuses on state, approvals, SoD, TTL, sensor kind/health/silence/capability/conflict', () => {
    const code = (over: Record<string, unknown>) => {
      const r = checkIpsEnable({
        ...base,
        ...over,
        sensor: { ...base.sensor, ...((over.sensor as object) ?? {}) },
      });
      return r.ok ? 'ok' : r.code;
    };
    expect(code({ status: 'pending_approval' })).toBe('bad_state');
    expect(code({ approverIds: ['a1'] })).toBe('insufficient_approvals');
    expect(code({ enablerId: 'a2' })).toBe('sod');
    expect(code({ enabledForHours: IPS_MAX_ENABLE_HOURS + 1 })).toBe('ttl');
    expect(code({ sensor: { kind: 'zeek' } })).toBe('sensor_kind');
    expect(code({ sensor: { enabled: false } })).toBe('sensor_disabled');
    expect(code({ sensor: { inlineCapable: false } })).toBe('not_inline_capable');
    expect(code({ sensor: { lastHeartbeatAt: new Date('2026-10-18T11:00:00Z') } })).toBe(
      'sensor_silent',
    );
    expect(code({ sensor: { lastHeartbeatAt: null } })).toBe('sensor_silent');
    expect(code({ sensor: { latestHealthState: 'degraded' } })).toBe('sensor_unhealthy');
    expect(code({ sensor: { hasEnabledPolicy: true } })).toBe('policy_conflict');
  });
  it('identifies public protected ranges and fails closed on garbage', () => {
    expect(publicCidrs(['10.0.0.0/8', '192.168.1.0/24', 'fd00::/8'])).toEqual([]);
    expect(publicCidrs(['10.0.0.0/8', '203.0.113.0/24'])).toEqual(['203.0.113.0/24']);
    expect(publicCidrs(['nonsense'])).toEqual(['nonsense']);
  });
  it('never allows a proposal in ids mode and requires rules, ranges and plans', () => {
    const ok = ProposeIpsPolicyRequest.safeParse({
      name: 'Drop known C2 to servers',
      sensorId: '11111111-1111-4111-8111-111111111111',
      mode: 'ips_test',
      protectedCidrs: ['10.10.0.0/16'],
      ruleIds: ['22222222-2222-4222-8222-222222222222'],
      justification: 'Validated ET C2 signatures only',
      rollbackPlan: 'Disable policy; sensor returns to ids on next fetch',
    });
    expect(ok.success).toBe(true);
    expect(ok.success && ok.data.action).toBe('drop');
    expect(ProposeIpsPolicyRequest.safeParse({ ...ok.data, mode: 'ids' }).success).toBe(false);
    expect(ProposeIpsPolicyRequest.safeParse({ ...ok.data, ruleIds: [] }).success).toBe(false);
    expect(ProposeIpsPolicyRequest.safeParse({ ...ok.data, rollbackPlan: 'none' }).success).toBe(
      false,
    );
  });
  it('directive contract is fail-open by construction', () => {
    const d = SensorIpsDirective.safeParse({
      mode: 'ids',
      policyId: null,
      version: 0,
      action: 'drop',
      protectedCidrs: [],
      excludedCidrs: [],
      ruleRefs: [],
      expiresAt: null,
      failOpen: false,
      issuedAt: now.toISOString(),
    });
    expect(d.success).toBe(false);
  });
});
