import { describe, expect, it } from 'vitest';
import {
  IPS_HEARTBEAT_MAX_AGE_SECONDS,
  conditionFingerprint,
  evaluateConditions,
  type ConditionInput,
} from '../src';

const now = new Date('2026-10-18T10:00:00Z');
const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000);
const ahead = (seconds: number) => new Date(now.getTime() + seconds * 1000);

const quiet: ConditionInput = {
  sensors: [{ name: 'ids-1', enabled: true, lastHeartbeatAt: ago(10), latestHealth: 'healthy' }],
  bundles: [{ sensorName: 'ids-1', inSync: true, expectedRuleCount: 3 }],
  ipsPolicies: [],
  analysis: { reachable: true, detail: null },
  pending: { ipsPolicies: 0, engagements: 0, responseActions: 0 },
  uncataloguedCves: [],
  assets: { total: 4, unmonitored: 1 },
};

describe('evaluateConditions', () => {
  it('reports every check even when nothing is wrong', () => {
    const r = evaluateConditions(quiet, now);
    expect(r.conditions).toEqual([]);
    expect(r.checks.map((c) => c.id).sort()).toEqual(
      [
        'analysis_reachable',
        'approvals_pending',
        'assets_unmonitored',
        'cves_uncatalogued',
        'detection_validation_failures',
        'ips_auto_disabled',
        'ips_policies_expiring',
        'rule_bundles_out_of_sync',
        'sensors_silent',
        'sensors_unhealthy',
      ].sort(),
    );
    expect(r.checks.every((c) => c.status === 'ok')).toBe(true);
  });

  it('raises silent, unhealthy and out-of-sync sensors, ordered by severity', () => {
    const r = evaluateConditions(
      {
        ...quiet,
        sensors: [
          { name: 'silent-1', enabled: true, lastHeartbeatAt: null, latestHealth: null },
          {
            name: 'stale-2',
            enabled: true,
            lastHeartbeatAt: ago(IPS_HEARTBEAT_MAX_AGE_SECONDS + 1),
            latestHealth: 'healthy',
          },
          { name: 'degraded-3', enabled: true, lastHeartbeatAt: ago(5), latestHealth: 'degraded' },
          { name: 'disabled-4', enabled: false, lastHeartbeatAt: null, latestHealth: null },
        ],
        bundles: [{ sensorName: 'degraded-3', inSync: false, expectedRuleCount: 2 }],
      },
      now,
    );
    expect(r.conditions.map((c) => [c.id, c.severity, c.count])).toEqual([
      ['sensors_silent', 'critical', 2],
      ['rule_bundles_out_of_sync', 'warning', 1],
      ['sensors_unhealthy', 'warning', 1],
    ]);
    const silent = r.conditions[0]!;
    expect(silent.detail).toContain('silent-1');
    expect(silent.detail).toContain('stale-2');
    expect(silent.detail).not.toContain('disabled-4');
    expect(silent.link).toBe('/nids');
  });

  it('flags expiring inline prevention and recent watchdog disables; ignores old ones', () => {
    const r = evaluateConditions(
      {
        ...quiet,
        ipsPolicies: [
          {
            name: 'soon',
            status: 'enabled',
            expiresAt: ahead(3600),
            disableCause: null,
            disabledAt: null,
          },
          {
            name: 'later',
            status: 'enabled',
            expiresAt: ahead(3 * 3600),
            disableCause: null,
            disabledAt: null,
          },
          {
            name: 'dropped',
            status: 'disabled',
            expiresAt: null,
            disableCause: 'sensor_unhealthy',
            disabledAt: ago(3600),
          },
          {
            name: 'old-drop',
            status: 'disabled',
            expiresAt: null,
            disableCause: 'sensor_unhealthy',
            disabledAt: ago(30 * 3600),
          },
          {
            name: 'manual',
            status: 'disabled',
            expiresAt: null,
            disableCause: 'operator',
            disabledAt: ago(60),
          },
        ],
      },
      now,
    );
    const ids = r.conditions.map((c) => c.id);
    expect(ids).toEqual(['ips_auto_disabled', 'ips_policies_expiring']);
    expect(r.conditions[0]!.detail).toContain('dropped');
    expect(r.conditions[0]!.detail).not.toContain('old-drop');
    expect(r.conditions[1]!.detail).toContain('soon');
    expect(r.conditions[1]!.detail).not.toContain('later');
  });

  it('distinguishes an unreachable analysis service from a probe that did not run', () => {
    const down = evaluateConditions(
      { ...quiet, analysis: { reachable: false, detail: 'ECONNREFUSED' } },
      now,
    );
    expect(down.conditions.map((c) => c.id)).toEqual(['analysis_unreachable']);
    expect(down.conditions[0]!.detail).toContain('ECONNREFUSED');
    const unknown = evaluateConditions({ ...quiet, analysis: null }, now);
    expect(unknown.conditions).toEqual([]);
    expect(unknown.checks.find((c) => c.id === 'analysis_reachable')?.status).toBe('unavailable');
  });

  it('reports informational conditions and the unmonitored-majority warning', () => {
    const r = evaluateConditions(
      {
        ...quiet,
        pending: { ipsPolicies: 1, engagements: 2, responseActions: 0 },
        uncataloguedCves: Array.from({ length: 10 }, (_, i) => `CVE-2026-${1000 + i}`),
        assets: { total: 10, unmonitored: 6 },
      },
      now,
    );
    expect(r.conditions.map((c) => [c.id, c.severity, c.count])).toEqual([
      ['assets_unmonitored', 'warning', 6],
      ['approvals_pending', 'info', 3],
      ['cves_uncatalogued', 'info', 10],
    ]);
    expect(r.conditions[2]!.detail).toMatch(/\+2$/);
    expect(r.conditions[0]!.detail).toContain('unknown, not low');
    // exactly half is not a majority; no assets at all is not a warning either
    expect(
      evaluateConditions({ ...quiet, assets: { total: 2, unmonitored: 1 } }, now).conditions,
    ).toEqual([]);
    expect(
      evaluateConditions({ ...quiet, assets: { total: 0, unmonitored: 0 } }, now).conditions,
    ).toEqual([]);
  });

  it('fingerprints change with severity or count, not with wording', () => {
    const base = {
      id: 'sensors_silent',
      severity: 'critical' as const,
      title: 'a',
      detail: 'x',
      count: 2,
      link: null,
    };
    expect(conditionFingerprint(base)).toBe(
      conditionFingerprint({ ...base, title: 'b', detail: 'y' }),
    );
    expect(conditionFingerprint(base)).not.toBe(conditionFingerprint({ ...base, count: 3 }));
    expect(conditionFingerprint(base)).not.toBe(
      conditionFingerprint({ ...base, severity: 'warning' }),
    );
  });
});

describe('detection validation condition', () => {
  it('raises a warning for failed validations and stuck schedules, naming them', () => {
    const r = evaluateConditions(
      {
        ...quiet,
        validations: {
          failedRules: ['1:9000001 CUSTOM C2'],
          scheduleErrors: ['ids-edge-1: sensor disabled'],
        },
      },
      now,
    );
    expect(r.conditions.map((c) => [c.id, c.severity, c.count])).toEqual([
      ['detection_validation_failures', 'warning', 2],
    ]);
    expect(r.conditions[0]!.detail).toContain('1:9000001 CUSTOM C2');
    expect(r.conditions[0]!.detail).toContain('ids-edge-1: sensor disabled');
    expect(r.conditions[0]!.link).toBe('/blue-team');
  });
});
