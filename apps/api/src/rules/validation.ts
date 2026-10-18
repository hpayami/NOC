import { HTTPException } from 'hono/http-exception';
import { and, desc, eq, gt, inArray, lt, sql, type SQL } from 'drizzle-orm';
import {
  VALIDATION_FRESH_DAYS,
  VALIDATION_TTL_MINUTES,
  bundleEngineFor,
  sidOfExternalId,
  validationVerdict,
  type CreateDetectionValidationRequest,
  type DetectionValidation,
  type DetectionValidationStatus,
  type SensorValidationDirective,
  type ValidationResultRequest,
  type ValidationVerdict,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { detectionRules, detectionValidations, sensors } from '../db/schema';
import { RuleService } from './service';

export interface Actor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

type Row = typeof detectionValidations.$inferSelect;

/**
 * Detection validation: an operator asks a sensor to replay a named sample *offline* against the
 * bundle it is running and report which signatures fired. The platform never ships packets, never
 * stores the sample, and only counts a result produced by the expected bundle. Queued requests
 * expire so a silent sensor never leaves a validation "pending" forever.
 */
export class ValidationService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  private toRecord(
    r: Row,
    rule: { name: string; externalId: string },
    sensorName: string,
  ): DetectionValidation {
    return {
      id: r.id,
      ruleId: r.ruleId,
      ruleName: rule.name,
      ruleExternalId: rule.externalId,
      sensorId: r.sensorId,
      sensorName,
      sampleRef: r.sampleRef,
      status: r.status as DetectionValidationStatus,
      expectedBundleSha256: r.expectedBundleSha256,
      reportedBundleSha256: r.reportedBundleSha256,
      expectedSids: r.expectedSids,
      firedSids: r.firedSids,
      missingSids: r.missingSids,
      unexpectedCount: r.unexpectedCount,
      verdict: (r.verdict as ValidationVerdict | null) ?? null,
      engineVersion: r.engineVersion,
      error: r.error,
      durationMs: r.durationMs,
      note: r.note,
      requestedBy: r.requestedBy,
      createdAt: r.createdAt.toISOString(),
      dispatchedAt: r.dispatchedAt?.toISOString() ?? null,
      reportedAt: r.reportedAt?.toISOString() ?? null,
      expiresAt: r.expiresAt.toISOString(),
    };
  }

  /** Anything still queued/dispatched past its deadline becomes `expired` (sensor never answered). */
  async expireDue(now = new Date()): Promise<number> {
    const rows = await this.db
      .update(detectionValidations)
      .set({ status: 'expired', error: 'sensor did not report before the deadline' })
      .where(
        and(
          inArray(detectionValidations.status, ['queued', 'dispatched']),
          lt(detectionValidations.expiresAt, now),
        ),
      )
      .returning({ id: detectionValidations.id });
    return rows.length;
  }

  async create(
    input: CreateDetectionValidationRequest,
    actor: Actor,
  ): Promise<DetectionValidation> {
    const [rule] = await this.db
      .select()
      .from(detectionRules)
      .where(eq(detectionRules.id, input.ruleId))
      .limit(1);
    if (!rule) throw new HTTPException(404, { message: 'Rule not found' });
    const [sensor] = await this.db
      .select()
      .from(sensors)
      .where(eq(sensors.id, input.sensorId))
      .limit(1);
    if (!sensor) throw new HTTPException(404, { message: 'Sensor not found' });
    const deny = async (reason: string) => {
      await this.audit.record({
        actorId: actor.userId,
        actorLabel: actor.label,
        action: 'detection_rules.validate',
        outcome: 'denied',
        targetType: 'detection_rule',
        targetId: rule.id,
        requestId: actor.requestId,
        sourceIp: actor.ip,
        metadata: { sensorId: sensor.id, sampleRef: input.sampleRef, reason },
      });
      throw new HTTPException(409, { message: reason });
    };
    if (rule.lifecycle !== 'deployed')
      await deny(`Rule is ${rule.lifecycle}; only deployed rules can be validated`);
    if (bundleEngineFor(sensor.kind) !== 'suricata')
      await deny(
        'Validation replays samples through Suricata; this sensor runs no Suricata bundle',
      );
    if (!sensor.enabled) await deny('Sensor is disabled');
    const sid = sidOfExternalId(rule.externalId);
    if (sid === null) await deny('Rule has no gid:sid identity to expect');
    const bundle = await new RuleService(this.db, this.audit).bundleFor({
      id: sensor.id,
      kind: sensor.kind,
      site: sensor.site,
    });
    if (!bundle || !bundle.rules.some((r) => r.id === rule.id))
      await deny('Rule is not part of the bundle this sensor receives (site targeting)');
    const now = new Date();
    const [row] = await this.db
      .insert(detectionValidations)
      .values({
        ruleId: rule.id,
        sensorId: sensor.id,
        sampleRef: input.sampleRef,
        status: 'queued',
        expectedBundleSha256: bundle!.bundleSha256,
        expectedSids: [sid!],
        note: input.note,
        requestedBy: actor.userId,
        createdAt: now,
        expiresAt: new Date(now.getTime() + VALIDATION_TTL_MINUTES * 60_000),
      })
      .returning();
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'detection_rules.validate',
      outcome: 'success',
      targetType: 'detection_rule',
      targetId: rule.id,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: {
        validationId: row!.id,
        sensorId: sensor.id,
        sampleRef: input.sampleRef,
        expectedSids: [sid],
      },
    });
    return this.toRecord(row!, rule, sensor.name);
  }

  /** Sensor side: hand out queued validations (marking them dispatched) — bounded per call. */
  async pendingFor(sensorId: string, now = new Date()): Promise<SensorValidationDirective[]> {
    await this.expireDue(now);
    const rows = await this.db
      .update(detectionValidations)
      .set({ status: 'dispatched', dispatchedAt: now })
      .where(
        and(
          eq(detectionValidations.sensorId, sensorId),
          eq(detectionValidations.status, 'queued'),
          gt(detectionValidations.expiresAt, now),
        ),
      )
      .returning();
    return rows.slice(0, 10).map((r) => ({
      id: r.id,
      sampleRef: r.sampleRef,
      expectedBundleSha256: r.expectedBundleSha256,
      expectedSids: r.expectedSids,
      expiresAt: r.expiresAt.toISOString(),
    }));
  }

  /** Sensor side: record what fired. The verdict is derived here, never trusted from the sensor. */
  async report(
    sensorId: string,
    id: string,
    input: ValidationResultRequest,
    now = new Date(),
  ): Promise<void> {
    const [row] = await this.db
      .select()
      .from(detectionValidations)
      .where(and(eq(detectionValidations.id, id), eq(detectionValidations.sensorId, sensorId)))
      .limit(1);
    if (!row) throw new HTTPException(404, { message: 'Validation not found for this sensor' });
    if (row.status !== 'dispatched' && row.status !== 'queued')
      throw new HTTPException(409, { message: `Validation is ${row.status}` });
    const v = validationVerdict({
      expectedSids: row.expectedSids,
      firedSids: input.firedSids,
      error: input.error,
      expectedBundleSha256: row.expectedBundleSha256,
      reportedBundleSha256: input.rulesBundleSha256,
    });
    await this.db
      .update(detectionValidations)
      .set({
        status: input.error ? 'failed' : 'completed',
        reportedBundleSha256: input.rulesBundleSha256,
        firedSids: [...new Set(input.firedSids)].slice(0, 10_000),
        missingSids: v.missingSids,
        unexpectedCount: v.unexpectedCount,
        verdict: v.verdict,
        engineVersion: input.engineVersion,
        error: v.detail,
        durationMs: input.durationMs,
        reportedAt: now,
      })
      .where(eq(detectionValidations.id, id));
    await this.audit.record({
      actorId: null,
      actorLabel: `sensor:${sensorId}`,
      action: 'detection_rules.validation_result',
      outcome: input.error ? 'failure' : 'success',
      targetType: 'detection_rule',
      targetId: row.ruleId,
      requestId: null,
      sourceIp: null,
      metadata: {
        validationId: id,
        verdict: v.verdict,
        fired: input.firedSids.length,
        missing: v.missingSids.length,
        detail: v.detail,
      },
    });
  }

  async list(q: {
    ruleId?: string;
    sensorId?: string;
    limit: number;
    sensorScope?: SQL;
  }): Promise<DetectionValidation[]> {
    await this.expireDue();
    const conds: SQL[] = [];
    if (q.ruleId) conds.push(eq(detectionValidations.ruleId, q.ruleId));
    if (q.sensorId) conds.push(eq(detectionValidations.sensorId, q.sensorId));
    if (q.sensorScope) conds.push(q.sensorScope);
    const rows = await this.db
      .select({
        v: detectionValidations,
        ruleName: detectionRules.name,
        ruleExternalId: detectionRules.externalId,
        sensorName: sensors.name,
      })
      .from(detectionValidations)
      .innerJoin(detectionRules, eq(detectionRules.id, detectionValidations.ruleId))
      .innerJoin(sensors, eq(sensors.id, detectionValidations.sensorId))
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(detectionValidations.createdAt))
      .limit(q.limit);
    return rows.map((r) =>
      this.toRecord(r.v, { name: r.ruleName, externalId: r.ruleExternalId }, r.sensorName),
    );
  }

  async get(id: string, sensorScope?: SQL): Promise<DetectionValidation> {
    const [r] = await this.list({
      limit: 1,
      sensorScope: sensorScope
        ? and(eq(detectionValidations.id, id), sensorScope)
        : eq(detectionValidations.id, id),
    });
    if (!r) throw new HTTPException(404, { message: 'Validation not found' });
    return r;
  }

  /**
   * Rules proven recently: a passed validation on a sensor that reported the bundle the rule is
   * currently part of. Scope restricts which sensors count.
   */
  async provenRuleIds(sensorScope: SQL | undefined, now = new Date()): Promise<Set<string>> {
    const since = new Date(now.getTime() - VALIDATION_FRESH_DAYS * 86_400_000);
    const rows = await this.db
      .select({ ruleId: detectionValidations.ruleId })
      .from(detectionValidations)
      .innerJoin(sensors, eq(sensors.id, detectionValidations.sensorId))
      .where(
        and(
          eq(detectionValidations.verdict, 'passed'),
          gt(detectionValidations.reportedAt, since),
          sql`${detectionValidations.reportedBundleSha256} = ${sensors.rulesBundleSha256}`,
          sensorScope,
        ),
      );
    return new Set(rows.map((r) => r.ruleId));
  }
}
