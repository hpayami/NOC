import { describe, expect, it } from 'vitest';
import {
  allowedNextStates,
  checkApproval,
  computeAlertPriority,
  deriveAssuranceState,
  deriveAssuranceStates,
  evaluateTarget,
  isPubliclyRoutable,
  requiredApprovals,
  validateIncidentTransition,
  type AuthorizedTargetScope,
} from '../src';

const scope = (over: Partial<AuthorizedTargetScope> = {}): AuthorizedTargetScope => ({
  includeCidrs: ['10.20.0.0/16'],
  includeAddresses: [],
  excludeCidrs: ['10.20.99.0/24'],
  excludeAddresses: ['10.20.1.1'],
  allowPublicAddresses: false,
  allowedTechniques: ['host_discovery', 'service_fingerprint'],
  windowStart: '2026-10-01T00:00:00Z',
  windowEnd: '2026-10-31T00:00:00Z',
  maxConcurrency: 4,
  maxRequestsPerSecond: 5,
  ...over,
});
const now = new Date('2026-10-18T12:00:00Z');
const base = { technique: 'host_discovery' as const, now };

describe('scope enforcement', () => {
  it('allows an in-scope private target inside the window', () => {
    expect(evaluateTarget({ scope: scope(), target: '10.20.5.9', ...base })).toEqual({
      allowed: true,
    });
  });
  it('exclusions win over inclusions', () => {
    expect(evaluateTarget({ scope: scope(), target: '10.20.99.7', ...base }).allowed).toBe(false);
    expect(evaluateTarget({ scope: scope(), target: '10.20.1.1', ...base }).allowed).toBe(false);
  });
  it('denies out-of-scope targets', () => {
    expect(evaluateTarget({ scope: scope(), target: '10.30.0.1', ...base }).allowed).toBe(false);
  });
  it('denies before the window and after expiry', () => {
    expect(
      evaluateTarget({
        scope: scope(),
        target: '10.20.5.9',
        technique: 'host_discovery',
        now: new Date('2026-09-30T00:00:00Z'),
      }).allowed,
    ).toBe(false);
    const expired = evaluateTarget({
      scope: scope(),
      target: '10.20.5.9',
      technique: 'host_discovery',
      now: new Date('2026-11-01T00:00:00Z'),
    });
    expect(expired.allowed).toBe(false);
    if (!expired.allowed) expect(expired.reasons.join()).toMatch(/expired/);
  });
  it('denies unauthorized techniques', () => {
    expect(
      evaluateTarget({ scope: scope(), target: '10.20.5.9', technique: 'vulnerability_scan', now })
        .allowed,
    ).toBe(false);
  });
  it('refuses public addresses even when listed, unless explicitly allowed', () => {
    const s = scope({ includeCidrs: ['8.8.8.0/24'] });
    expect(evaluateTarget({ scope: s, target: '8.8.8.8', ...base }).allowed).toBe(false);
    expect(
      evaluateTarget({ scope: { ...s, allowPublicAddresses: true }, target: '8.8.8.8', ...base })
        .allowed,
    ).toBe(true);
  });
  it('fails closed on garbage and hostnames', () => {
    expect(evaluateTarget({ scope: scope(), target: 'example.com', ...base }).allowed).toBe(false);
    expect(evaluateTarget({ scope: scope(), target: '10.20.5.9; rm -rf /', ...base }).allowed).toBe(
      false,
    );
  });
  it('handles IPv4-mapped IPv6 so scope cannot be bypassed by notation', () => {
    expect(evaluateTarget({ scope: scope(), target: '::ffff:10.20.99.7', ...base }).allowed).toBe(
      false,
    );
    expect(evaluateTarget({ scope: scope(), target: '::ffff:10.20.5.9', ...base }).allowed).toBe(
      true,
    );
  });
  it('classifies routability', () => {
    expect(isPubliclyRoutable('192.168.1.1')).toBe(false);
    expect(isPubliclyRoutable('fd00::1')).toBe(false);
    expect(isPubliclyRoutable('1.1.1.1')).toBe(true);
  });
});

describe('incident lifecycle', () => {
  it('walks the standard forward chain', () => {
    const chain = [
      'new',
      'triage',
      'investigation',
      'containment',
      'eradication',
      'recovery',
      'closed',
    ] as const;
    for (let i = 0; i < chain.length - 1; i++) {
      expect(
        validateIncidentTransition({ type: 'security', from: chain[i]!, to: chain[i + 1]! }).ok,
      ).toBe(true);
    }
  });
  it('rejects skipping phases for security incidents', () => {
    expect(
      validateIncidentTransition({ type: 'security', from: 'new', to: 'containment' }).ok,
    ).toBe(false);
    expect(
      validateIncidentTransition({
        type: 'security',
        from: 'investigation',
        to: 'recovery',
        reason: 'long enough reason',
      }).ok,
    ).toBe(false);
  });
  it('allows documented deviations only with a reason', () => {
    expect(
      validateIncidentTransition({ type: 'noc_outage', from: 'investigation', to: 'recovery' }),
    ).toMatchObject({
      ok: false,
      code: 'reason_required',
    });
    expect(
      validateIncidentTransition({
        type: 'noc_outage',
        from: 'investigation',
        to: 'recovery',
        reason: 'No eradication phase for link outage',
      }).ok,
    ).toBe(true);
    expect(
      validateIncidentTransition({
        type: 'security',
        from: 'triage',
        to: 'closed',
        reason: 'False positive: scanner test',
      }),
    ).toMatchObject({ ok: true, requiresPermission: 'incidents.close' });
  });
  it('closed incidents can only be reopened to investigation', () => {
    expect(allowedNextStates('security', 'closed')).toEqual(['investigation']);
    expect(
      validateIncidentTransition({
        type: 'security',
        from: 'closed',
        to: 'new',
        reason: 'reopen please ok',
      }).ok,
    ).toBe(false);
  });
  it('rejects no-op transitions', () => {
    expect(validateIncidentTransition({ type: 'security', from: 'new', to: 'new' })).toMatchObject({
      ok: false,
      code: 'same_state',
    });
  });
});

describe('assurance states', () => {
  const ok = {
    monitored: true,
    detectionCapable: true,
    sensorHealthy: true,
    telemetryFresh: true,
    telemetryComplete: true,
    assessmentPerformed: true,
    openFindings: 0,
    activeAlerts: 0,
  };
  it('never reports no_threat_detected for unmonitored assets', () => {
    expect(deriveAssuranceState({ ...ok, monitored: false })).toBe('asset_not_monitored');
  });
  it('visibility gaps outrank missing alerts', () => {
    expect(deriveAssuranceState({ ...ok, detectionCapable: false })).toBe('detection_unavailable');
    expect(deriveAssuranceState({ ...ok, sensorHealthy: false })).toBe('sensor_unhealthy');
    expect(deriveAssuranceState({ ...ok, telemetryFresh: false })).toBe('telemetry_incomplete');
    expect(deriveAssuranceState({ ...ok, telemetryComplete: false })).toBe('telemetry_incomplete');
  });
  it('reports no_threat_detected only with full visibility and no alerts', () => {
    expect(deriveAssuranceStates(ok)).toEqual(['no_threat_detected']);
    expect(deriveAssuranceStates({ ...ok, activeAlerts: 2 })).not.toContain('no_threat_detected');
  });
  it('separates assessment dimensions', () => {
    expect(deriveAssuranceStates({ ...ok, assessmentPerformed: false })).toEqual([
      'assessment_not_performed',
      'no_threat_detected',
    ]);
    expect(deriveAssuranceState({ ...ok, openFindings: 3 })).toBe('assessment_with_findings');
  });
});

describe('alert priority', () => {
  it('is monotonic in severity, confidence and criticality', () => {
    const p = (
      severity: 'low' | 'high',
      confidence: 'low' | 'high',
      assetCriticality: 'low' | 'critical',
    ) => computeAlertPriority({ severity, confidence, assetCriticality }).score;
    expect(p('high', 'high', 'low')).toBeGreaterThan(p('low', 'high', 'low'));
    expect(p('high', 'high', 'low')).toBeGreaterThan(p('high', 'low', 'low'));
    expect(p('high', 'high', 'critical')).toBeGreaterThan(p('high', 'high', 'low'));
  });
  it('is bounded and explainable', () => {
    const r = computeAlertPriority({
      severity: 'critical',
      confidence: 'high',
      assetCriticality: 'critical',
    });
    expect(r.score).toBeLessThanOrEqual(100);
    expect(r.factors).toHaveLength(3);
  });
});

describe('response approvals', () => {
  const input = {
    kind: 'block_indicator' as const,
    status: 'pending_approval',
    proposedBy: 'u1',
    approverId: 'u2',
    approverPermissions: new Set(['response.approve' as const]),
    priorApproverIds: [] as string[],
    expiresAt: null,
    now,
  };
  it('approves with an independent approver holding the permission', () => {
    expect(checkApproval(input).ok).toBe(true);
  });
  it('blocks self approval, duplicates, missing permission, wrong state and expiry', () => {
    expect(checkApproval({ ...input, approverId: 'u1' })).toMatchObject({ code: 'self_approval' });
    expect(checkApproval({ ...input, priorApproverIds: ['u2'] })).toMatchObject({
      code: 'duplicate_approver',
    });
    expect(checkApproval({ ...input, approverPermissions: new Set() })).toMatchObject({
      code: 'forbidden',
    });
    expect(checkApproval({ ...input, status: 'executed' })).toMatchObject({ code: 'bad_state' });
    expect(checkApproval({ ...input, expiresAt: new Date('2026-10-18T11:00:00Z') })).toMatchObject({
      code: 'expired',
    });
  });
  it('requires two approvers for inline prevention and isolation', () => {
    expect(requiredApprovals('enable_inline_prevention')).toBe(2);
    expect(requiredApprovals('isolate_endpoint')).toBe(2);
    expect(requiredApprovals('recommend_isolation')).toBe(0);
  });
});
