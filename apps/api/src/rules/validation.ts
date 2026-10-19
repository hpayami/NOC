import { HTTPException } from 'hono/http-exception';
import { and, desc, eq, gt, inArray, lt, or, sql, type SQL } from 'drizzle-orm';
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

/** One page of schedules; the list endpoint never silently truncates beyond this. */
const SCHEDULE_PAGE_LIMIT = 200;
/** Schedules examined per scheduler tick. */
const SCHEDULE_BATCH_LIMIT = 1000;
/** Validation rows read per tick to decide the batch (newest attempt + newest pass per pair). */
const SCHEDULE_HISTORY_LIMIT = 20_000;
/**
 * Postgres advisory-lock key: one scheduler pass at a time across every API instance. Exported
 * so a test can hold the same lock and prove a concurrent pass stands down.
 */
export const SCHEDULE_LOCK_KEY = 0x6e6f6356;

/**
 * A timestamp that arrives either as a `Date` (a mapped column) or as text (an aggregate the
 * driver does not map). Both are accepted; unparseable values read as "never".
 */
const asDate = (v: Date | string | null | undefined): Date | null => {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};

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

  /**
   * Anything still queued/dispatched past its deadline becomes `expired` (sensor never answered).
   * The expiry *stamps* `reportedAt`, so a sensor that simply never answers still counts as a
   * recent attempt and the schedule backs off for a full interval instead of re-queueing on
   * every scheduler tick.
   */
  async expireDue(now = new Date()): Promise<number> {
    const rows = await this.db
      .update(detectionValidations)
      .set({
        status: 'expired',
        error: 'sensor did not report before the deadline',
        reportedAt: now,
      })
      .where(
        and(
          inArray(detectionValidations.status, ['queued', 'dispatched']),
          lt(detectionValidations.expiresAt, now),
        ),
      )
      .returning({ id: detectionValidations.id });
    return rows.length;
  }

  /**
   * Queue one validation for a rule on a sensor. Everything the deployment state refuses is a
   * 409 the caller can act on; a sensor outside the caller's site scope reads as missing (404),
   * so a scoped caller can neither discover nor act on sensors at sites they do not hold.
   */
  async create(
    input: CreateDetectionValidationRequest,
    actor: Actor,
    sensorScope?: SQL,
  ): Promise<DetectionValidation> {
    const [rule] = await this.db
      .select()
      .from(detectionRules)
      .where(eq(detectionRules.id, input.ruleId))
      .limit(1);
    // An unattributable rule or sensor reads as missing, not as a permission error: a sensor
    // outside the caller's site scope is invisible to them, so it cannot be used as an oracle.
    if (!rule) throw new HTTPException(404, { message: 'Rule not found' });
    const [sensor] = await this.db
      .select()
      .from(sensors)
      .where(
        sensorScope
          ? and(eq(sensors.id, input.sensorId), sensorScope)
          : eq(sensors.id, input.sensorId),
      )
      .limit(1);
    if (!sensor) throw new HTTPException(404, { message: 'Sensor not found' });
    // Rule lifecycle, sensor kind/enabled and bundle membership are conditions of the
    // deployment state — not permissions — so they are reported as a conflict the caller
    // can act on, and are stored on the schedule as `lastError`.
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

  /** Newest-first, `limit` rows per page; pass the previous page's `nextCursor` for the next. */
  private async scheduleRecords(
    where: SQL | undefined,
    limit = SCHEDULE_PAGE_LIMIT,
  ): Promise<ValidationSchedule[]> {
    const rows = await this.db
      .select({
        s: validationSchedules,
        ruleName: detectionRules.name,
        ruleExternalId: detectionRules.externalId,
        sensorName: sensors.name,
        lastVerdict: sql<ValidationVerdict | null>`
          (select v.verdict from detection_validations v
           where v.rule_id = ${validationSchedules.ruleId}
             and v.sensor_id = ${validationSchedules.sensorId}
             and v.verdict is not null
           order by v.reported_at desc nulls last limit 1)`,
        lastVerdictAt: sql<Date | null>`
          (select v.reported_at from detection_validations v
           where v.rule_id = ${validationSchedules.ruleId}
             and v.sensor_id = ${validationSchedules.sensorId}
             and v.verdict is not null
           order by v.reported_at desc nulls last limit 1)`,
      })
      .from(validationSchedules)
      .innerJoin(detectionRules, eq(detectionRules.id, validationSchedules.ruleId))
      .innerJoin(sensors, eq(sensors.id, validationSchedules.sensorId))
      .where(where)
      .orderBy(desc(validationSchedules.createdAt), desc(validationSchedules.id))
      .limit(limit);
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
      lastVerdict: r.lastVerdict,
      lastVerdictAt: r.lastVerdictAt ? new Date(r.lastVerdictAt).toISOString() : null,
    }));
  }

  /**
   * Schedules newest-first, capped at one page. `cursor` is the id of the last row of the
   * previous page. A cursor that names no row (or one outside the caller's site scope) returns
   * the first page rather than erroring, so a stale link cannot be used to probe for ids.
   */
  async listSchedules(
    sensorScope: SQL | undefined,
    opts: { limit?: number; cursor?: string } = {},
  ): Promise<{ items: ValidationSchedule[]; nextCursor: string | null }> {
    const limit = Math.min(Math.max(opts.limit ?? SCHEDULE_PAGE_LIMIT, 1), SCHEDULE_PAGE_LIMIT);
    const conds: SQL[] = [];
    if (sensorScope) conds.push(sensorScope);
    // Keyset pagination on (created_at, id) keeps pages stable while rows are inserted.
    const anchor = opts.cursor
      ? await this.db
          .select({
            createdAt: validationSchedules.createdAt,
            id: validationSchedules.id,
          })
          .from(validationSchedules)
          .where(
            sensorScope
              ? and(eq(validationSchedules.id, opts.cursor), sensorScope)
              : eq(validationSchedules.id, opts.cursor),
          )
          .limit(1)
      : [];
    if (anchor[0])
      conds.push(
        // ISO string, not a raw Date: drizzle/postgres-js cannot bind a Date inside a row
        // constructor comparison (ERR_INVALID_ARG_TYPE on the driver's cache path).
        sql`(${validationSchedules.createdAt}, ${validationSchedules.id}) < (${anchor[0].createdAt.toISOString()}, ${anchor[0].id})`,
      );
    const page = await this.scheduleRecords(conds.length ? and(...conds) : undefined, limit + 1);
    const hasMore = page.length > limit;
    const items = hasMore ? page.slice(0, limit) : page;
    return { items, nextCursor: hasMore ? (items.at(-1)?.id ?? null) : null };
  }

  /**
   * Create (or re-open) a schedule for one rule on one sensor. The sensor must be inside the
   * caller's site scope; a schedule that already exists is *reconfigured* rather than silently
   * overwritten, and its next run is queued now so the caller sees it take effect.
   */
  async createSchedule(
    input: CreateValidationScheduleRequest,
    actor: Actor,
    sensorScope?: SQL,
  ): Promise<ValidationSchedule> {
    // Same admission as a one-off validation — site scope included — and it also queues the
    // first run right away.
    const first = await this.create(
      {
        ruleId: input.ruleId,
        sensorId: input.sensorId,
        sampleRef: input.sampleRef,
        note: input.note,
      },
      actor,
      sensorScope,
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
    sensorScope?: SQL,
  ): Promise<ValidationSchedule> {
    // The scope condition names `sensors`, so the lookup must join it; then update by id.
    const conds: SQL[] = [eq(validationSchedules.id, id)];
    if (sensorScope) conds.push(sensorScope);
    const [found] = await this.db
      .select({ id: validationSchedules.id, ruleId: validationSchedules.ruleId })
      .from(validationSchedules)
      .innerJoin(sensors, eq(sensors.id, validationSchedules.sensorId))
      .where(and(...conds))
      .limit(1);
    // Out of scope reads as missing, so the id cannot be used as an existence oracle.
    if (!found) throw new HTTPException(404, { message: 'Schedule not found' });
    await this.db
      .update(validationSchedules)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(validationSchedules.id, found.id));
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'detection_rules.validation_schedule',
      outcome: 'success',
      targetType: 'detection_rule',
      targetId: found.ruleId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: { scheduleId: id, ...patch },
    });
    const [rec] = await this.scheduleRecords(eq(validationSchedules.id, id));
    return rec!;
  }

  async runSchedules(
    now = new Date(),
  ): Promise<{ queued: number; skipped: number; errors: number }> {
    const out = { queued: 0, skipped: 0, errors: 0 };
    // One pass at a time across every API instance: take a session-level advisory lock and drop
    // it again on the *same* pooled connection. That only holds if both statements run inside a
    // transaction, because `db.execute` otherwise picks a connection per query and an unlock on
    // a different session is a no-op — the lock would leak and every later pass would silently
    // do nothing. An instance that finds the lock busy skips this tick; the next one gets it.
    await this.db.transaction(async (tx) => {
      const locked = (await tx.execute(
        sql`select pg_try_advisory_lock(${SCHEDULE_LOCK_KEY}) as locked`,
      )) as unknown as Array<{ locked: boolean }>;
      if (locked[0]?.locked !== true) return;
      try {
        await this.pass(now, out);
      } finally {
        await tx.execute(sql`select pg_advisory_unlock(${SCHEDULE_LOCK_KEY})`);
      }
    });
    return out;
  }

  /**
   * The scheduler pass itself: for every enabled schedule whose last *pass* is older than its
   * interval (or that never passed) and that has nothing queued or dispatched, queue a
   * validation on behalf of the schedule's creator. A failed, inconclusive, or expired attempt
   * is not retried before the interval elapses either, so a broken sample — or a sensor that
   * never answers — does not queue a validation every tick. Admission refusals land on the
   * schedule as `lastError` for the condition check.
   *
   * The two facts each schedule needs (its latest attempt, and its latest *pass*) come back in
   * two queries for the whole batch, not two per schedule.
   */
  private async pass(
    now: Date,
    out: { queued: number; skipped: number; errors: number },
  ): Promise<void> {
    // Sweep expiries first: an unanswered validation must look like a recent attempt.
    await this.expireDue(now);
    const rows = await this.db
      .select()
      .from(validationSchedules)
      .where(eq(validationSchedules.enabled, true))
      .limit(SCHEDULE_BATCH_LIMIT);
    if (!rows.length) return;

    const pairs = or(
      ...rows.map((s) =>
        and(
          eq(detectionValidations.ruleId, s.ruleId),
          eq(detectionValidations.sensorId, s.sensorId),
        ),
      ),
    );
    // The newest attempt per pair. `reported_at` is stamped on every outcome (report or
    // expiry), so `createdAt` is only a tiebreaker for rows that have not resolved yet.
    const attempts = await this.db
      .select()
      .from(detectionValidations)
      .where(pairs)
      .orderBy(desc(detectionValidations.createdAt))
      .limit(SCHEDULE_HISTORY_LIMIT);
    // The newest *pass* per pair, as one aggregate over the same rows.
    const passes = await this.db
      .select({
        ruleId: detectionValidations.ruleId,
        sensorId: detectionValidations.sensorId,
        passedAt: sql<Date | null>`max(${detectionValidations.reportedAt})`,
      })
      .from(detectionValidations)
      .where(and(pairs, eq(detectionValidations.verdict, 'passed')))
      .groupBy(detectionValidations.ruleId, detectionValidations.sensorId);

    // Rows are ordered newest-first, so the first row seen for a pair is its newest attempt.
    const latest = new Map<string, (typeof attempts)[number]>();
    for (const a of attempts) {
      const key = `${a.ruleId}:${a.sensorId}`;
      if (!latest.has(key)) latest.set(key, a);
    }
    const lastPass = new Map<string, Date | null>(
      passes.map((p) => [`${p.ruleId}:${p.sensorId}`, p.passedAt]),
    );

    for (const s of rows) {
      const key = `${s.ruleId}:${s.sensorId}`;
      const attempt = latest.get(key);
      if (attempt && (attempt.status === 'queued' || attempt.status === 'dispatched')) {
        out.skipped++;
        continue;
      }
      const interval = s.intervalDays * 86_400_000;
      const passedAt = asDate(lastPass.get(key));
      const due = !passedAt || now.getTime() - passedAt.getTime() >= interval;
      const reportedAt = asDate(attempt?.reportedAt);
      const attemptedRecently = !!reportedAt && now.getTime() - reportedAt.getTime() < interval;
      if (!due || (attempt && attempt.verdict !== 'passed' && attemptedRecently)) {
        out.skipped++;
        continue;
      }
      try {
        await this.create(
          { ruleId: s.ruleId, sensorId: s.sensorId, sampleRef: s.sampleRef, note: s.note },
          {
            userId: s.createdBy,
            label: 'system:validation-scheduler',
            requestId: null,
            ip: null,
          },
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
