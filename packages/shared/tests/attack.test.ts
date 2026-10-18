import { describe, expect, it } from 'vitest';
import { assessAssetRisk, exposureTechniques, techniqueInfo } from '../src';

describe('ATT&CK attribution and asset risk', () => {
  it('names only catalogued techniques and maps exposures without pretending they were observed', () => {
    expect(techniqueInfo('T1021.002')).toEqual({
      name: 'SMB/Windows Admin Shares',
      tactic: 'lateral-movement',
    });
    expect(techniqueInfo('T9999')).toEqual({ name: null, tactic: null });
    expect(exposureTechniques(445)).toEqual(['T1021.002', 'T1210']);
    expect(exposureTechniques(8443)).toEqual([]);
  });

  it('reports unknown — never safe — for an unmonitored asset without evidence', () => {
    const r = assessAssetRisk({
      monitoringCoverage: 'unmonitored',
      assuranceState: 'asset_not_monitored',
      openFindings: [],
      openAlerts: [],
      exposures: [],
      criticality: 'unclassified',
    });
    expect(r.level).toBe('unknown');
    expect(r.confidence).toBe('low');
    expect(r.basis.join(' ')).toMatch(/absence of alerts is not evidence of safety/);
  });

  it('scores monotonically from findings, alerts and risky exposures and explains each input', () => {
    const base = {
      monitoringCoverage: 'monitored',
      assuranceState: 'no_threat_detected',
      openFindings: [],
      openAlerts: [],
      exposures: [],
      criticality: 'unclassified',
    };
    const clean = assessAssetRisk(base);
    expect(clean).toMatchObject({ level: 'none', score: 0, confidence: 'high' });
    const exposed = assessAssetRisk({
      ...base,
      exposures: [
        { port: 445, severity: 'medium' },
        { port: 8080, severity: null },
      ],
    });
    expect(exposed.level).toBe('low');
    expect(exposed.basis.join(' ')).toMatch(/2 open port\(s\), 1 on risky services \(445\)/);
    const alerted = assessAssetRisk({
      ...base,
      openAlerts: [{ severity: 'high' }, { severity: 'medium' }],
    });
    expect(alerted.score).toBeGreaterThan(exposed.score);
    expect(alerted.level).toBe('medium');
    const found = assessAssetRisk({
      ...base,
      openFindings: [{ severity: 'critical', validated: true }],
      openAlerts: [{ severity: 'high' }],
    });
    expect(found.level).toBe('critical');
    const amplified = assessAssetRisk({
      ...base,
      criticality: 'critical',
      openFindings: [{ severity: 'high', validated: false }],
    });
    expect(amplified.basis.join(' ')).toMatch(/criticality critical amplifies/);
    expect(amplified.basis.join(' ')).toMatch(/some unvalidated/);
    expect(amplified.score).toBeGreaterThan(
      assessAssetRisk({ ...base, openFindings: [{ severity: 'high', validated: false }] }).score,
    );
    // Degraded telemetry lowers confidence, not the level.
    expect(
      assessAssetRisk({
        ...base,
        assuranceState: 'sensor_unhealthy',
        exposures: [{ port: 23, severity: 'high' }],
      }).confidence,
    ).toBe('medium');
  });
});
