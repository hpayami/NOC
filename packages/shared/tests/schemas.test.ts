import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import {
  Alert,
  Approval,
  Asset,
  AssetInterface,
  AssetObservation,
  AssessmentEngagement,
  AuditEvent,
  CreateUserRequest,
  DetectionRule,
  Incident,
  LoginRequest,
  MlInferenceResult,
  MonitoringPolicy,
  NetworkFlow,
  NetworkSegment,
  NormalizedEvent,
  PASSWORD_MIN_LENGTH,
  PERMISSIONS,
  ROLE_DEFINITIONS,
  ROLE_KEYS,
  RemediationTask,
  ResponseAction,
  RetentionPolicy,
  Role,
  SEPARATED_PERMISSION_PAIRS,
  Sensor,
  SensorHealth,
  ThreatIndicator,
  TopologyRelationship,
  User,
  VulnerabilityFinding,
  permissionsForRoles,
} from '../src';

const uuid = '3f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a11';
const ts = '2026-10-18T12:00:00Z';

describe('RBAC catalog', () => {
  it('only references known permissions and has no duplicates per role', () => {
    for (const key of ROLE_KEYS) {
      const perms = ROLE_DEFINITIONS[key].permissions;
      expect(new Set(perms).size).toBe(perms.length);
      for (const p of perms) expect(PERMISSIONS).toContain(p);
    }
  });
  it('enforces separation of duties inside every role', () => {
    for (const key of ROLE_KEYS) {
      const held = permissionsForRoles([key]);
      for (const [a, b] of SEPARATED_PERMISSION_PAIRS) {
        expect(held.has(a) && held.has(b), `${key} holds both ${a} and ${b}`).toBe(false);
      }
    }
  });
  it('gives no role the whole catalog (least privilege)', () => {
    for (const key of ROLE_KEYS)
      expect(permissionsForRoles([key]).size).toBeLessThan(PERMISSIONS.length / 2);
  });
  it('keeps high-impact permissions out of the read-only auditor role', () => {
    const auditor = permissionsForRoles(['read_only_auditor']);
    for (const p of [
      'ips.enable',
      'response.execute',
      'assessments.execute',
      'evidence.export',
      'retention.modify',
    ] as const) {
      expect(auditor.has(p)).toBe(false);
    }
  });
});

describe('schema strictness', () => {
  it('rejects unknown keys on strict schemas', () => {
    expect(LoginRequest.safeParse({ email: 'a@b.co', password: 'x', extra: 1 }).success).toBe(
      false,
    );
  });
  it('enforces password length on user creation', () => {
    const ok = CreateUserRequest.safeParse({
      email: 'a@b.co',
      displayName: 'A',
      password: 'x'.repeat(PASSWORD_MIN_LENGTH),
      roles: [],
    });
    const short = CreateUserRequest.safeParse({
      email: 'a@b.co',
      displayName: 'A',
      password: 'short',
      roles: [],
    });
    expect(ok.success).toBe(true);
    expect(short.success).toBe(false);
  });
  it('validates normalized events and bounds engine fields', () => {
    const ev = {
      schemaVersion: '1.0',
      eventId: uuid,
      eventTime: ts,
      ingestTime: ts,
      sourceProduct: 'suricata',
      sourceSensorId: null,
      category: 'network',
      type: 'alert',
      severity: 'high',
      confidence: 'medium',
      srcAssetId: null,
      dstAssetId: null,
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 4444,
      dstPort: 443,
      protocol: 'tcp',
      ruleId: '2100498',
      threatClassification: ['T1046'],
      incidentId: null,
      evidenceRefs: [],
      correlationIds: [],
      originalRef: null,
      engine: { sid: 1 },
    };
    expect(NormalizedEvent.safeParse(ev).success).toBe(true);
    expect(NormalizedEvent.safeParse({ ...ev, schemaVersion: '2.0' }).success).toBe(false);
    expect(NormalizedEvent.safeParse({ ...ev, srcIp: 'not-an-ip' }).success).toBe(false);
    expect(NormalizedEvent.safeParse({ ...ev, srcPort: 70000 }).success).toBe(false);
    expect(NormalizedEvent.safeParse({ ...ev, threatClassification: ['DROP TABLE'] }).success).toBe(
      false,
    );
    expect(NormalizedEvent.safeParse({ ...ev, engine: { blob: 'x'.repeat(20_000) } }).success).toBe(
      false,
    );
    expect(NormalizedEvent.safeParse({ ...ev, rawPayload: 'AAAA' }).success).toBe(false);
  });
  it('treats ML output as advisory only', () => {
    const base = {
      id: uuid,
      modelName: 'm',
      modelVersion: '1',
      featureSetVersion: '1',
      subjectType: 'flow',
      subjectId: 'x',
      score: 0.4,
      explanation: [],
      evidenceRefs: [],
      createdAt: ts,
    };
    expect(MlInferenceResult.safeParse({ ...base, advisory: true }).success).toBe(true);
    expect(MlInferenceResult.safeParse({ ...base, advisory: false }).success).toBe(false);
  });
});

describe('public schemas never expose secret-bearing fields', () => {
  const FORBIDDEN =
    /password|passwd|secret|token|credential|private_?key|hash|mfa_?secret|rawpayload|payload/i;
  // Integrity digests and a status enum (credentialed assessment state) — none carry secret material.
  const ALLOWED = new Set([
    'prevHash',
    'hash',
    'contentSha256',
    'sha256',
    'credentialedAssessmentStatus',
  ]);

  function keysOf(schema: z.ZodType, seen = new Set<z.ZodType>()): string[] {
    if (seen.has(schema)) return [];
    seen.add(schema);
    const def = (schema as unknown as { _zod: { def: Record<string, unknown> } })._zod.def;
    const type = def.type as string;
    if (type === 'object') {
      const shape = def.shape as Record<string, z.ZodType>;
      return Object.entries(shape).flatMap(([k, v]) => [k, ...keysOf(v, seen)]);
    }
    if (type === 'union') return (def.options as z.ZodType[]).flatMap((o) => keysOf(o, seen));
    const inner = (def.innerType ?? def.element ?? def.in ?? def.valueType) as
      z.ZodType | undefined;
    return inner ? keysOf(inner, seen) : [];
  }

  const schemas: Record<string, z.ZodType> = {
    User,
    Role,
    Asset,
    AssetInterface,
    AssetObservation,
    NetworkSegment,
    TopologyRelationship,
    Sensor,
    SensorHealth,
    NetworkFlow,
    Alert,
    Incident,
    VulnerabilityFinding,
    AssessmentEngagement,
    DetectionRule,
    ThreatIndicator,
    RemediationTask,
    ResponseAction,
    Approval,
    AuditEvent,
    MonitoringPolicy,
    RetentionPolicy,
    MlInferenceResult,
    NormalizedEvent,
  };
  for (const [name, schema] of Object.entries(schemas)) {
    it(`${name} has no credential-like keys`, () => {
      const bad = keysOf(schema).filter((k) => FORBIDDEN.test(k) && !ALLOWED.has(k));
      expect(bad).toEqual([]);
    });
  }
});
