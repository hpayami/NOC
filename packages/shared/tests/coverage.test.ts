import { describe, expect, it } from 'vitest';
import { ATTACK_TECHNIQUES, computeCoverage, engineOfRuleSource } from '../src';

const now = new Date('2026-10-18T10:00:00Z');

describe('detection coverage', () => {
  it('maps rule sources to the engine that consumes them', () => {
    expect(engineOfRuleSource('zeek_script')).toBe('zeek');
    expect(engineOfRuleSource('et_open')).toBe('suricata');
    expect(engineOfRuleSource('custom')).toBe('suricata');
  });

  it('counts a technique covered only when a deployed rule is acknowledged by a running sensor', () => {
    const c = computeCoverage(
      {
        rules: [
          { lifecycle: 'deployed', techniques: ['T1046'], engine: 'suricata' },
          { lifecycle: 'deployed', techniques: ['T1110', 'T1110.001'], engine: 'zeek' },
          { lifecycle: 'validated', techniques: ['T1190'], engine: 'suricata' },
          { lifecycle: 'draft', techniques: ['T1190'], engine: 'suricata' },
          { lifecycle: 'disabled', techniques: ['T1021.004'], engine: 'suricata' },
          { lifecycle: 'retired', techniques: ['T1040'], engine: 'suricata' },
          { lifecycle: 'deployed', techniques: ['T9999'], engine: 'suricata' },
        ],
        sensors: [
          { engine: 'suricata', enabled: true, inSync: true },
          { engine: 'suricata', enabled: true, inSync: false },
          { engine: 'zeek', enabled: true, inSync: false },
          { engine: null, enabled: true, inSync: false },
        ],
        observed: { T1046: 12, T1110: 3, T1595: 7 },
        openAlerts: { T1046: 2 },
        exposed: { T1190: 4, 'T1021.004': 2, T1046: 1 },
        periodDays: 30,
      },
      now,
    );
    const by = Object.fromEntries(c.rows.map((r) => [r.technique, r]));
    expect(by.T1046).toMatchObject({
      status: 'covered',
      name: 'Network Service Discovery',
      tactic: 'discovery',
      sensorsInSync: 1,
      observedInPeriod: 12,
      openAlerts: 2,
      exposedAssets: 1,
    });
    expect(by.T1110).toMatchObject({
      status: 'deployed_unacknowledged',
      sensorsInSync: 0,
      observedInPeriod: 3,
    });
    expect(by.T1190).toMatchObject({
      status: 'rule_not_deployed',
      rules: { total: 2, deployed: 0, validated: 1, draft: 1, disabled: 0 },
      exposedAssets: 4,
    });
    expect(by['T1021.004']).toMatchObject({ status: 'rule_not_deployed', rules: { disabled: 1 } });
    expect(by.T1040).toMatchObject({ status: 'uncovered', rules: { total: 0 } }); // retired rules do not count
    expect(by.T1595).toMatchObject({ status: 'uncovered', observedInPeriod: 7 });
    expect(by.T9999).toMatchObject({ status: 'covered', name: null, tactic: null }); // outside the catalogue, kept
    expect(c.summary).toMatchObject({
      techniques: Object.keys(ATTACK_TECHNIQUES).length + 1,
      covered: 2,
      deployedUnacknowledged: 2, // T1110 and T1110.001 share the unacknowledged zeek rule
      ruleNotDeployed: 2,
      exposedUncovered: 2, // T1190 and T1021.004
      observedUncovered: 2, // T1110 (deployed but unacknowledged) and T1595
      sensors: {
        enabled: 3,
        inSync: 1,
        byEngine: { suricata: { enabled: 2, inSync: 1 }, zeek: { enabled: 1, inSync: 0 } },
      },
    });
    expect(c.summary.byTactic.discovery).toEqual({ total: 2, covered: 1 });
    expect(c.summary.byTactic.unknown).toEqual({ total: 1, covered: 1 });
    expect(c.rows.map((r) => r.technique)).toEqual([...c.rows.map((r) => r.technique)].sort());
    expect(c.limitations.some((l) => /not because it is safe/.test(l))).toBe(true);
  });

  it('reports everything uncovered on an empty platform rather than nothing', () => {
    const c = computeCoverage(
      { rules: [], sensors: [], observed: {}, openAlerts: {}, exposed: {}, periodDays: 7 },
      now,
    );
    expect(c.summary.techniques).toBe(Object.keys(ATTACK_TECHNIQUES).length);
    expect(c.summary.uncovered).toBe(c.summary.techniques);
    expect(c.summary.sensors).toEqual({ enabled: 0, inSync: 0, byEngine: {} });
  });
});
