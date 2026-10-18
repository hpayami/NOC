import { eq, sql } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  AUDIT_RETENTION_FLOOR_DAYS,
  RetentionDataClassValues,
  type RetentionDataClass,
  type RetentionDatasetReport,
  type RetentionPolicy,
  type RetentionRunReport,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { retentionPolicies } from '../db/schema';

/** Defaults applied when a class has no policy row yet. Conservative; operators tighten or extend. */
export const DEFAULT_RETENTION_DAYS: Record<RetentionDataClass, number> = {
  security_events: 30,
  raw_events: 7,
  flows: 14,
  audit: AUDIT_RETENTION_FLOOR_DAYS,
  evidence: 365,
  metrics: 30,
  observations: 90,
  pcap: 3,
};

interface Dataset {
  table: string;
  timeColumn: string;
  /** Extra predicate; rows matching it are never purged (e.g. attached to an incident). */
  keep?: string;
}

/**
 * Where each data class lives today. Classes without a store are reported as `dataset_absent`
 * rather than silently "purged". The audit trail is never a purge target.
 */
const DATASETS: Partial<Record<RetentionDataClass, Dataset[]>> = {
  security_events: [
    { table: 'security_events', timeColumn: 'event_time', keep: 'incident_id is not null' },
  ],
  metrics: [
    { table: 'check_results', timeColumn: 'observed_at' },
    { table: 'asset_metrics', timeColumn: 'observed_at' },
    { table: 'sensor_health', timeColumn: 'recorded_at' },
  ],
  observations: [{ table: 'asset_observations', timeColumn: 'observed_at' }],
};
const PROTECTED: ReadonlySet<RetentionDataClass> = new Set(['audit']);

const toPolicy = (r: typeof retentionPolicies.$inferSelect): RetentionPolicy => ({
  id: r.id,
  dataClass: r.dataClass,
  retentionDays: r.retentionDays,
  legalHold: r.legalHold,
  updatedAt: r.updatedAt.toISOString(),
});

export class RetentionService {
  lastRun: RetentionRunReport | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly opts: { batchSize?: number; maxBatchesPerDataset?: number } = {},
  ) {}

  /** Inserts default rows for classes that have none; existing policies are never touched. */
  async ensureDefaults(): Promise<void> {
    await this.db
      .insert(retentionPolicies)
      .values(
        RetentionDataClassValues.map((dataClass) => ({
          dataClass,
          retentionDays: DEFAULT_RETENTION_DAYS[dataClass],
        })),
      )
      .onConflictDoNothing({ target: retentionPolicies.dataClass });
  }

  async list(): Promise<RetentionPolicy[]> {
    await this.ensureDefaults();
    const rows = await this.db
      .select()
      .from(retentionPolicies)
      .orderBy(retentionPolicies.dataClass);
    return rows.map(toPolicy);
  }

  async update(
    dataClass: RetentionDataClass,
    input: { retentionDays: number; legalHold: boolean },
    actor: { userId: string; email: string; requestId: string | null; ip: string | null },
  ): Promise<RetentionPolicy> {
    if (dataClass === 'audit' && input.retentionDays < AUDIT_RETENTION_FLOOR_DAYS)
      throw new RetentionError(
        `Audit retention cannot be below ${AUDIT_RETENTION_FLOOR_DAYS} days`,
      );
    await this.ensureDefaults();
    const row = await this.db.transaction(async (tx) => {
      const [before] = await tx
        .select()
        .from(retentionPolicies)
        .where(eq(retentionPolicies.dataClass, dataClass))
        .for('update');
      const [after] = await tx
        .update(retentionPolicies)
        .set({
          retentionDays: input.retentionDays,
          legalHold: input.legalHold,
          updatedBy: actor.userId,
          updatedAt: new Date(),
        })
        .where(eq(retentionPolicies.dataClass, dataClass))
        .returning();
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.email,
          action: 'retention.modify',
          outcome: 'success',
          targetType: 'retention_policy',
          targetId: after!.id,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: {
            dataClass,
            from: before
              ? { retentionDays: before.retentionDays, legalHold: before.legalHold }
              : null,
            to: { retentionDays: input.retentionDays, legalHold: input.legalHold },
          },
        },
        tx,
      );
      return after!;
    });
    return toPolicy(row);
  }

  /**
   * Purges rows past each policy's cutoff in bounded batches (so a backlog never turns into one
   * long-running delete). Deletions are audited in aggregate; nothing is audited for a no-op run.
   */
  async run(
    trigger: 'scheduled' | 'manual',
    actor?: { userId: string; email: string; requestId: string | null; ip: string | null },
    now = new Date(),
  ): Promise<RetentionRunReport> {
    const startedAt = now;
    const policies = await this.list();
    const batchSize = this.opts.batchSize ?? 5000;
    const maxBatches = this.opts.maxBatchesPerDataset ?? 20;
    const datasets: RetentionDatasetReport[] = [];
    for (const p of policies) {
      const cutoff = new Date(now.getTime() - p.retentionDays * 86_400_000);
      const base = {
        dataClass: p.dataClass,
        retentionDays: p.retentionDays,
        cutoff: cutoff.toISOString(),
      };
      if (PROTECTED.has(p.dataClass)) {
        datasets.push({
          ...base,
          dataset: 'audit_events',
          deleted: 0,
          outcome: 'protected',
          detail: 'The audit trail is never purged automatically',
        });
        continue;
      }
      const targets = DATASETS[p.dataClass];
      if (!targets) {
        datasets.push({
          ...base,
          dataset: p.dataClass,
          deleted: 0,
          outcome: 'dataset_absent',
          detail: 'No store exists for this class yet',
        });
        continue;
      }
      for (const t of targets) {
        if (p.legalHold) {
          datasets.push({
            ...base,
            dataset: t.table,
            deleted: 0,
            outcome: 'legal_hold',
            detail: null,
          });
          continue;
        }
        try {
          let deleted = 0;
          let batches = 0;
          let more = true;
          while (more && batches < maxBatches) {
            const n = await this.deleteBatch(t, cutoff, batchSize);
            deleted += n;
            batches++;
            more = n === batchSize;
          }
          datasets.push({
            ...base,
            dataset: t.table,
            deleted,
            outcome: more ? 'truncated' : 'purged',
            detail: more ? `stopped after ${maxBatches} batches; more rows remain` : null,
          });
        } catch (err) {
          datasets.push({
            ...base,
            dataset: t.table,
            deleted: 0,
            outcome: 'failed',
            detail: err instanceof Error ? err.message.slice(0, 512) : 'unknown error',
          });
        }
      }
    }
    const totalDeleted = datasets.reduce((a, d) => a + d.deleted, 0);
    const report: RetentionRunReport = {
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      trigger,
      datasets,
      totalDeleted,
    };
    this.lastRun = report;
    const failed = datasets.filter((d) => d.outcome === 'failed');
    if (totalDeleted > 0 || failed.length > 0 || trigger === 'manual') {
      await this.audit.record({
        actorId: actor?.userId ?? null,
        actorLabel: actor?.email ?? 'system:retention',
        action: 'retention.run',
        outcome: failed.length ? 'failure' : 'success',
        targetType: 'retention',
        targetId: null,
        requestId: actor?.requestId ?? null,
        sourceIp: actor?.ip ?? null,
        metadata: {
          trigger,
          totalDeleted,
          datasets: datasets.map((d) => ({
            dataset: d.dataset,
            deleted: d.deleted,
            outcome: d.outcome,
          })),
        },
      });
    }
    return report;
  }

  private async deleteBatch(t: Dataset, cutoff: Date, limit: number): Promise<number> {
    // Table and column names come from the static DATASETS map above, never from input.
    const table = sql.raw(t.table);
    const keep = t.keep ? sql.raw(` and not (${t.keep})`) : sql.raw('');
    const res = await this.db.execute(
      sql`delete from ${table} where id in (select id from ${table} where ${sql.raw(t.timeColumn)} < ${cutoff.toISOString()}::timestamptz${keep} limit ${limit}) returning id`,
    );
    return (res as unknown as { length: number }).length;
  }
}

export class RetentionError extends Error {}

/** Periodic retention enforcement; one run at a time, errors logged, never crashes the API. */
export class RetentionScheduler {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly svc: RetentionService,
    private readonly opts: { intervalMinutes: number; logger: Logger },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.intervalMinutes * 60_000);
    this.timer.unref();
    this.opts.logger.info(
      { intervalMinutes: this.opts.intervalMinutes },
      'retention scheduler started',
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
      const r = await this.svc.run('scheduled');
      if (r.totalDeleted > 0)
        this.opts.logger.info({ totalDeleted: r.totalDeleted }, 'retention run');
    } catch (err) {
      this.opts.logger.error({ err }, 'retention run failed');
    } finally {
      this.running = false;
    }
  }
}
