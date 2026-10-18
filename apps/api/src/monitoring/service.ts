import net from 'node:net';
import { and, eq, inArray, isNull, lte, or, sql } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  SENSOR_HEARTBEAT_TIMEOUT_SECONDS,
  deriveOperationalStatus,
  deriveSensorHealth,
  isWindowActive,
  type CheckEvidence,
  type CheckOutcome,
  type SensorHealthState,
} from '@noc/shared';
import type { Db, DbTx } from '../db/client';
import {
  assets,
  checkResults,
  maintenanceWindows,
  monitoringChecks,
  sensorHealth,
  sensors,
} from '../db/schema';

type Exec = Db | DbTx;

export interface SensorState {
  derivedState: SensorHealthState;
  heartbeatAgeSeconds: number | null;
}

/** Derives a sensor's current state from its heartbeat age and its last self-reported health. */
export async function sensorState(
  db: Exec,
  sensorId: string,
  now: Date,
): Promise<SensorState | null> {
  const [s] = await db
    .select({ lastHeartbeatAt: sensors.lastHeartbeatAt })
    .from(sensors)
    .where(eq(sensors.id, sensorId))
    .limit(1);
  if (!s) return null;
  const [latest] = await db
    .select({ state: sensorHealth.state })
    .from(sensorHealth)
    .where(eq(sensorHealth.sensorId, sensorId))
    .orderBy(sql`${sensorHealth.recordedAt} desc`)
    .limit(1);
  const heartbeatAgeSeconds = s.lastHeartbeatAt
    ? (now.getTime() - s.lastHeartbeatAt.getTime()) / 1000
    : null;
  return {
    derivedState: deriveSensorHealth({
      lastHeartbeatAt: s.lastHeartbeatAt,
      now,
      reportedState: latest?.state ?? null,
    }),
    heartbeatAgeSeconds,
  };
}

export async function isAssetInMaintenance(
  db: Exec,
  assetId: string,
  segmentId: string | null,
  now: Date,
): Promise<boolean> {
  const rows = await db
    .select({ startsAt: maintenanceWindows.startsAt, endsAt: maintenanceWindows.endsAt })
    .from(maintenanceWindows)
    .where(
      and(
        lte(maintenanceWindows.startsAt, now),
        sql`${maintenanceWindows.endsAt} > ${now.toISOString()}::timestamptz`,
        or(
          eq(maintenanceWindows.assetId, assetId),
          segmentId ? eq(maintenanceWindows.segmentId, segmentId) : sql`false`,
        ),
      ),
    )
    .limit(1);
  return rows.some((w) => isWindowActive(w, now));
}

export class AvailabilityService {
  constructor(private readonly db: Db) {}

  /** Recomputes and stores an asset's operational status from its checks, collectors and windows. */
  async reevaluateAsset(db: Exec, assetId: string, now = new Date()): Promise<string> {
    const [asset] = await db
      .select({ id: assets.id, segmentId: assets.segmentId, coverage: assets.monitoringCoverage })
      .from(assets)
      .where(eq(assets.id, assetId))
      .limit(1);
    if (!asset) return 'unknown';
    const checks = await db
      .select()
      .from(monitoringChecks)
      .where(and(eq(monitoringChecks.assetId, assetId), eq(monitoringChecks.enabled, true)));
    const latestByCheck = new Map<string, { outcome: CheckOutcome; observedAt: Date }>();
    if (checks.length) {
      const rows = (await db.execute(
        sql`select distinct on (check_id) check_id, outcome, observed_at from check_results where check_id in (${sql.join(
          checks.map((c) => sql`${c.id}::uuid`),
          sql`, `,
        )}) order by check_id, observed_at desc`,
      )) as unknown as Array<{
        check_id: string;
        outcome: CheckOutcome;
        observed_at: Date | string;
      }>;
      for (const r of rows)
        latestByCheck.set(r.check_id, { outcome: r.outcome, observedAt: new Date(r.observed_at) });
    }
    const collectorCache = new Map<string, SensorState | null>();
    const evidence: CheckEvidence[] = [];
    for (const c of checks) {
      let collector: CheckEvidence['collector'] = 'platform';
      if (c.collectorId) {
        if (!collectorCache.has(c.collectorId))
          collectorCache.set(c.collectorId, await sensorState(db, c.collectorId, now));
        const st = collectorCache.get(c.collectorId);
        collector = {
          heartbeatAgeSeconds: st?.heartbeatAgeSeconds ?? null,
          timeoutSeconds: SENSOR_HEARTBEAT_TIMEOUT_SECONDS,
        };
      }
      evidence.push({
        intervalSeconds: c.intervalSeconds,
        latest: latestByCheck.get(c.id) ?? null,
        collector,
      });
    }
    const inMaintenance = await isAssetInMaintenance(db, assetId, asset.segmentId, now);
    const { status } = deriveOperationalStatus({ checks: evidence, now, inMaintenance });
    await db
      .update(assets)
      .set({
        operationalStatus: status,
        // Availability checks give partial coverage; only a security sensor can make it "monitored".
        monitoringCoverage:
          checks.length > 0 && asset.coverage !== 'monitored' ? 'partial' : asset.coverage,
        updatedAt: now,
      })
      .where(eq(assets.id, assetId));
    return status;
  }
}

/** TCP connect probe with a hard timeout. Never sends application data. */
export function runTcpCheck(
  target: string,
  port: number,
  timeoutMs: number,
): Promise<{ outcome: CheckOutcome; latencyMs: number | null; detail: string | null }> {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const socket = new net.Socket();
    let settled = false;
    const finish = (outcome: CheckOutcome, detail: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const latencyMs = outcome === 'up' ? Number(process.hrtime.bigint() - started) / 1e6 : null;
      resolve({ outcome, latencyMs: latencyMs === null ? null : Math.round(latencyMs), detail });
    };
    socket.setTimeout(timeoutMs, () => finish('timeout', `no connection within ${timeoutMs} ms`));
    socket.once('connect', () => finish('up', null));
    socket.once('error', (err: NodeJS.ErrnoException) =>
      finish(
        err.code === 'ECONNREFUSED' || err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH'
          ? 'down'
          : 'error',
        err.code ?? err.message,
      ),
    );
    socket.connect({ host: target, port });
  });
}

export interface SchedulerOptions {
  tickSeconds: number;
  maxConcurrency: number;
  logger: Logger;
}

/**
 * In-process executor for platform-run checks (collectorId = null). Picks due checks, probes them
 * with bounded concurrency, stores results and re-evaluates the affected assets.
 */
export class MonitoringScheduler {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly db: Db,
    private readonly availability: AvailabilityService,
    private readonly opts: SchedulerOptions,
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.tickSeconds * 1000);
    this.timer.unref();
    this.opts.logger.info({ tickSeconds: this.opts.tickSeconds }, 'monitoring scheduler started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const n = await this.runDueChecks(new Date());
      if (n > 0) this.opts.logger.debug({ executed: n }, 'monitoring tick');
    } catch (err) {
      this.opts.logger.error({ err }, 'monitoring tick failed');
    } finally {
      this.running = false;
    }
  }

  /** Executes every platform-run check that is due at `now`. Returns the number executed. */
  async runDueChecks(now: Date, limit = 200): Promise<number> {
    const due = await this.db
      .select()
      .from(monitoringChecks)
      .where(
        and(
          eq(monitoringChecks.enabled, true),
          isNull(monitoringChecks.collectorId),
          or(
            isNull(monitoringChecks.lastRunAt),
            sql`${monitoringChecks.lastRunAt} + make_interval(secs => ${monitoringChecks.intervalSeconds}) <= ${now.toISOString()}::timestamptz`,
          ),
        ),
      )
      .limit(limit);
    if (due.length === 0) return 0;

    const touched = new Set<string>();
    const queue = [...due];
    const worker = async () => {
      for (let c = queue.shift(); c; c = queue.shift()) {
        const result =
          c.kind === 'tcp' && c.port !== null
            ? await runTcpCheck(c.target, c.port, c.timeoutMs)
            : {
                outcome: 'unsupported' as const,
                latencyMs: null,
                detail: `${c.kind} checks are not executed by the management plane`,
              };
        await this.db.insert(checkResults).values({
          checkId: c.id,
          observedAt: now,
          outcome: result.outcome,
          latencyMs: result.latencyMs,
          detail: result.detail,
          collectorState: 'platform',
        });
        await this.db
          .update(monitoringChecks)
          .set({ lastRunAt: now })
          .where(eq(monitoringChecks.id, c.id));
        touched.add(c.assetId);
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(this.opts.maxConcurrency, due.length) }, worker),
    );
    for (const assetId of touched) await this.availability.reevaluateAsset(this.db, assetId, now);
    return due.length;
  }
}

/** Convenience for routes: re-evaluate several assets after bulk changes. */
export async function reevaluateMany(
  av: AvailabilityService,
  db: Exec,
  assetIds: string[],
  now = new Date(),
): Promise<void> {
  for (const id of new Set(assetIds)) await av.reevaluateAsset(db, id, now);
}

export { inArray };
