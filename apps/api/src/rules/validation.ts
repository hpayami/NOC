import { HTTPException } from 'hono/http-exception';
import { and, desc, eq, gt, inArray, lt, sql, type SQL } from 'drizzle-orm';
import {
  VALIDATION_FRESH_DAYS,
  VALIDATION_TTL_MINUTES,
  bundleEngineFor,
  sidOfExternalId,
  validationVerdict,
  type CreateDetectionValidationRequest,
  type CreateValidationScheduleRequest,
  type ValidationSchedule,
  type DetectionValidation,
  type DetectionValidationStatus,
  type SensorValidationDirective,
  type ValidationResultRequest,
  type ValidationVerdict,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { detectionRules, detectionValidations, sensors, validationSchedules } from '../db/schema';
import type { Logger } from 'pino';
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

  // ---- schedules ---------------------------------------------------------------------------
  private async scheduleRecords(where?: SQL): Promise<ValidationSchedule[]> {
    const rows = await this.db
      .select({
        s: validationSchedules,
        ruleName: detectionRules.name,
        ruleExternalId: detectionRules.externalId,
        sensorName: sensors.name,
        lastVerdict: sql<
          string | null
        >`(select v.verdict from detection_validations v where v.rule_id = ${validationSchedules.ruleId} and v.sensor_id = ${validationSchedules.sensorId} and v.verdict is not null order by v.reported_at desc limit 1)`,
        lastVerdictAt: sql<
          string | null
        >`(select v.reported_at from detection_validations v where v.rule_id = ${validationSchedules.ruleId} and v.sensor_id = ${validationSchedules.sensorId} and v.verdict is not null order by v.reported_at desc limit 1)`,
      })
      .from(validationSchedules)
      .innerJoin(detectionRules, eq(detectionRules.id, validationSchedules.ruleId))
      .innerJoin(sensors, eq(sensors.id, validationSchedules.sensorId))
      .where(where)
      .orderBy(desc(validationSchedules.createdAt))
      .limit(500);
    return rows.map((r) => ({
      id: r.s.id,
      ruleId: r.s.ruleId,
      ruleName: r.ruleName,
      ruleExternalId: r.ruleExternalId,
      sensorId: r.s.sensorId,
      sensorName: r.sensorName,
      sampleRef: r.s.sampleRef,
      intervalDays: r.s.intervalDays,
      enabled: r.s.enabled,
      note: r.s.note,
      createdBy: r.s.createdBy,
      createdAt: r.s.createdAt.toISOString(),
      lastQueuedAt: r.s.lastQueuedAt?.toISOString() ?? null,
      lastError: r.s.lastError,
      lastVerdict: (r.lastVerdict as ValidationVerdict | null) ?? null,
      lastVerdictAt: r.lastVerdictAt ? new Date(r.lastVerdictAt).toISOString() : null,
    }));
  }

  async listSchedules(sensorScope?: SQL): Promise<ValidationSchedule[]> {
    return this.scheduleRecords(sensorScope);
  }

  async createSchedule(
    input: CreateValidationScheduleRequest,
    actor: Actor,
  ): Promise<ValidationSchedule> {
    // Same admission as a one-off validation; it also queues the first run right away.
    const first = await this.create(
      {
        ruleId: input.ruleId,
        sensorId: input.sensorId,
        sampleRef: input.sampleRef,
        note: input.note,
      },
      actor,
    );
    const now = new Date();
    const [row] = await this.db
      .insert(validationSchedules)
      .values({
        ruleId: input.ruleId,
        sensorId: input.sensorId,
        sampleRef: input.sampleRef,
        intervalDays: input.intervalDays,
        note: input.note,
        createdBy: actor.userId,
        createdAt: now,
        updatedAt: now,
        lastQueuedAt: now,
      })
      .onConflictDoUpdate({
        target: [validationSchedules.ruleId, validationSchedules.sensorId],
        set: {
          sampleRef: input.sampleRef,
          intervalDays: input.intervalDays,
          note: input.note,
          enabled: true,
          updatedAt: now,
          lastQueuedAt: now,
          lastError: null,
        },
      })
      .returning({ id: validationSchedules.id });
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'detection_rules.validation_schedule',
      outcome: 'success',
      targetType: 'detection_rule',
      targetId: input.ruleId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: {
        scheduleId: row!.id,
        sensorId: input.sensorId,
        intervalDays: input.intervalDays,
        firstValidationId: first.id,
      },
    });
    const [rec] = await this.scheduleRecords(eq(validationSchedules.id, row!.id));
    return rec!;
  }

  async updateSchedule(
    id: string,
    patch: { enabled?: boolean; intervalDays?: number },
    actor: Actor,
  ): Promise<ValidationSchedule> {
    const [row] = await this.db
      .update(validationSchedules)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(validationSchedules.id, id))
      .returning({ id: validationSchedules.id, ruleId: validationSchedules.ruleId });
    if (!row) throw new HTTPException(404, { message: 'Schedule not found' });
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'detection_rules.validation_schedule',
      outcome: 'success',
      targetType: 'detection_rule',
      targetId: row.ruleId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: { scheduleId: id, ...patch },
    });
    const [rec] = await this.scheduleRecords(eq(validationSchedules.id, id));
    return rec!;
  }

  /**
   * One scheduler pass: for every enabled schedule whose last *pass* is older than its interval
   * (or that never passed) and that has nothing queued or dispatched, queue a validation on
   * behalf of the schedule's creator. A failed or inconclusive attempt is not retried before the
   * interval elapses either, so a broken sample does not queue a validation every tick.
   * Admission refusals land on the schedule as `lastError` for the condition check.
   */
  async runSchedules(
    now = new Date(),
  ): Promise<{ queued: number; skipped: number; errors: number }> {
    const out = { queued: 0, skipped: 0, errors: 0 };
    const rows = await this.db
      .select()
      .from(validationSchedules)
      .where(eq(validationSchedules.enabled, true))
      .limit(1000);
    for (const s of rows) {
      const [latest] = await this.db
        .select({
          status: detectionValidations.status,
          verdict: detectionValidations.verdict,
          reportedAt: detectionValidations.reportedAt,
        })
        .from(detectionValidations)
        .where(
          and(
            eq(detectionValidations.ruleId, s.ruleId),
            eq(detectionValidations.sensorId, s.sensorId),
          ),
        )
        .orderBy(desc(detectionValidations.createdAt))
        .limit(1);
      if (latest && (latest.status === 'queued' || latest.status === 'dispatched')) {
        out.skipped++;
        continue;
      }
      const [lastPass] = await this.db
        .select({ reportedAt: detectionValidations.reportedAt })
        .from(detectionValidations)
        .where(
          and(
            eq(detectionValidations.ruleId, s.ruleId),
            eq(detectionValidations.sensorId, s.sensorId),
            eq(detectionValidations.verdict, 'passed'),
          ),
        )
        .orderBy(desc(detectionValidations.reportedAt))
        .limit(1);
      const interval = s.intervalDays * 86_400_000;
      const due =
        !lastPass?.reportedAt || now.getTime() - lastPass.reportedAt.getTime() >= interval;
      const attemptedRecently =
        !!latest?.reportedAt && now.getTime() - latest.reportedAt.getTime() < interval;
      if (!due || (latest && latest.verdict !== 'passed' && attemptedRecently)) {
        out.skipped++;
        continue;
      }
      try {
        await this.create(
          { ruleId: s.ruleId, sensorId: s.sensorId, sampleRef: s.sampleRef, note: s.note },
          { userId: s.createdBy, label: 'system:validation-scheduler', requestId: null, ip: null },
        );
        await this.db
          .update(validationSchedules)
          .set({ lastQueuedAt: now, lastError: null })
          .where(eq(validationSchedules.id, s.id));
        out.queued++;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await this.db
          .update(validationSchedules)
          .set({ lastError: message.slice(0, 512), updatedAt: now })
          .where(eq(validationSchedules.id, s.id));
        out.errors++;
      }
    }
    return out;
  }

  /** Input for the platform-conditions check. */
  async conditionInput(
    now = new Date(),
  ): Promise<{ failedRules: string[]; scheduleErrors: string[] }> {
    const since = new Date(now.getTime() - VALIDATION_FRESH_DAYS * 86_400_000);
    const failed = (await this.db.execute(sql`
      select distinct r.external_id || ' ' || r.name as label
      from detection_validations v
      join detection_rules r on r.id = v.rule_id
      where r.lifecycle = 'deployed' and v.verdict = 'failed' and v.reported_at > ${since.toISOString()}::timestamptz
        and v.reported_at = (select max(v2.reported_at) from detection_validations v2 where v2.rule_id = v.rule_id and v2.sensor_id = v.sensor_id and v2.verdict is not null)
      order by 1 limit 50`)) as unknown as Array<{ label: string }>;
    const stuck = await this.db
      .select({ sensorName: sensors.name, error: validationSchedules.lastError })
      .from(validationSchedules)
      .innerJoin(sensors, eq(sensors.id, validationSchedules.sensorId))
      .where(
        and(
          eq(validationSchedules.enabled, true),
          sql`${validationSchedules.lastError} is not null`,
        ),
      )
      .limit(50);
    return {
      failedRules: failed.map((f) => f.label),
      scheduleErrors: stuck.map((s) => `${s.sensorName}: ${s.error}`),
    };
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

export class ValidationScheduler {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly svc: ValidationService,
    private readonly opts: { intervalSeconds: number; logger: Logger },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.intervalSeconds * 1000);
    this.timer.unref();
    this.opts.logger.info(
      { intervalSeconds: this.opts.intervalSeconds },
      'validation scheduler started',
    );
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const r = await this.svc.runSchedules();
      if (r.queued || r.errors) this.opts.logger.info(r, 'validation schedules cycle');
    } catch (err) {
      this.opts.logger.error({ err }, 'validation schedules cycle failed');
    } finally {
      this.running = false;
    }
  }
}
