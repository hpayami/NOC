import { createHmac } from 'node:crypto';
import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, inArray, sql } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  CONDITION_SEVERITY_RANK,
  conditionFingerprint,
  evaluateConditions,
  type ConditionSeverity,
  type CreateNotificationChannelRequest,
  type NotificationChannel,
  type NotificationDelivery,
  type PlatformCondition,
  type PlatformConditions,
  type WebhookPayload,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import {
  assessmentEngagements,
  assets,
  ipsPolicies,
  notificationChannels,
  notificationDeliveries,
  notificationStates,
  responseActions,
  sensors,
} from '../db/schema';
import type { MlService } from '../ml/service';
import { RuleService } from '../rules/service';
import { VulnerabilityService } from '../vulnerabilities/service';

export interface Actor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

type ChannelRow = typeof notificationChannels.$inferSelect;

const toChannel = (c: ChannelRow): NotificationChannel => ({
  id: c.id,
  name: c.name,
  kind: 'webhook',
  url: c.url,
  enabled: c.enabled,
  minSeverity: c.minSeverity as ConditionSeverity,
  createdAt: c.createdAt.toISOString(),
  lastAttemptAt: c.lastAttemptAt?.toISOString() ?? null,
  lastStatus: (c.lastStatus as 'sent' | 'failed' | null) ?? null,
  lastError: c.lastError,
});

const toDelivery = (d: typeof notificationDeliveries.$inferSelect): NotificationDelivery => ({
  id: d.id,
  channelId: d.channelId,
  conditionId: d.conditionId,
  event: d.event as NotificationDelivery['event'],
  severity: d.severity as ConditionSeverity,
  status: d.status as NotificationDelivery['status'],
  httpStatus: d.httpStatus,
  error: d.error,
  attemptedAt: d.attemptedAt.toISOString(),
});

export function signWebhook(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

/**
 * Platform conditions (what an operator should act on) and their delivery to webhook channels.
 * Evaluation is pure (`evaluateConditions`) over records the platform already holds; delivery
 * is signed, bounded, de-duplicated per channel and condition, reminded after a quiet period,
 * and every attempt is recorded — a failed webhook is visible, never silently dropped.
 */
export class OperationsService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly ml: Pick<MlService, 'status'>,
    private readonly opts: {
      version: string;
      remindHours: number;
      logger: Logger;
      fetchImpl?: typeof fetch;
      timeoutMs?: number;
    },
  ) {}

  async conditions(now = new Date()): Promise<PlatformConditions> {
    const sensorRows = await this.db
      .select({
        name: sensors.name,
        enabled: sensors.enabled,
        lastHeartbeatAt: sensors.lastHeartbeatAt,
        // Written out in full: a single-table select renders `${sensors.id}` unqualified, which the
        // subquery would resolve against sensor_health's own id column.
        latestHealth: sql<
          string | null
        >`(select h.state from sensor_health h where h.sensor_id = sensors.id order by h.recorded_at desc limit 1)`,
      })
      .from(sensors)
      .limit(1000);
    const bundles = (await new RuleService(this.db, this.audit).deploymentState(null))
      .filter((d) => d.engine !== null)
      .map((d) => ({
        sensorName: d.sensorName,
        inSync: d.inSync,
        expectedRuleCount: d.expectedRuleCount,
      }));
    const policies = await this.db
      .select({
        name: ipsPolicies.name,
        status: ipsPolicies.status,
        expiresAt: ipsPolicies.expiresAt,
        disableCause: ipsPolicies.disableCause,
        disabledAt: ipsPolicies.disabledAt,
      })
      .from(ipsPolicies)
      .where(
        sql`${ipsPolicies.status} in ('enabled', 'pending_approval') or (${ipsPolicies.disableCause} = 'sensor_unhealthy' and ${ipsPolicies.disabledAt} > ${new Date(now.getTime() - 24 * 3_600_000).toISOString()}::timestamptz)`,
      )
      .limit(500);
    let analysis: { reachable: boolean; detail: string | null } | null = null;
    try {
      const st = await this.ml.status();
      analysis = { reachable: st.reachable, detail: st.detail };
    } catch {
      analysis = null;
    }
    const [eng] = await this.db
      .select({ n: count() })
      .from(assessmentEngagements)
      .where(eq(assessmentEngagements.status, 'pending_approval'));
    const [ra] = await this.db
      .select({ n: count() })
      .from(responseActions)
      .where(eq(responseActions.status, 'pending_approval'));
    const uncatalogued = await new VulnerabilityService(this.db, this.audit).uncatalogued(20);
    const [assetCounts] = await this.db
      .select({
        total: count(),
        unmonitored: sql<number>`count(*) filter (where ${assets.monitoringCoverage} = 'unmonitored')::int`,
      })
      .from(assets);
    const r = evaluateConditions(
      {
        sensors: sensorRows,
        bundles,
        ipsPolicies: policies,
        analysis,
        pending: {
          ipsPolicies: policies.filter((p) => p.status === 'pending_approval').length,
          engagements: eng?.n ?? 0,
          responseActions: ra?.n ?? 0,
        },
        uncataloguedCves: uncatalogued,
        assets: {
          total: assetCounts?.total ?? 0,
          unmonitored: Number(assetCounts?.unmonitored ?? 0),
        },
      },
      now,
    );
    return { ...r, evaluatedAt: now.toISOString() };
  }

  // ---- channels ---------------------------------------------------------------------------
  async createChannel(
    input: CreateNotificationChannelRequest,
    actor: Actor,
  ): Promise<NotificationChannel> {
    const [row] = await this.db
      .insert(notificationChannels)
      .values({
        name: input.name,
        url: input.url,
        secret: input.secret,
        enabled: input.enabled,
        minSeverity: input.minSeverity,
        createdBy: actor.userId,
      })
      .returning();
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'notifications.channel_create',
      outcome: 'success',
      targetType: 'notification_channel',
      targetId: row!.id,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: { name: input.name, url: input.url, minSeverity: input.minSeverity },
    });
    return toChannel(row!);
  }

  async updateChannel(
    id: string,
    patch: { enabled?: boolean; minSeverity?: ConditionSeverity },
    actor: Actor,
  ): Promise<NotificationChannel> {
    const [row] = await this.db
      .update(notificationChannels)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(notificationChannels.id, id))
      .returning();
    if (!row) throw new HTTPException(404, { message: 'Channel not found' });
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'notifications.channel_update',
      outcome: 'success',
      targetType: 'notification_channel',
      targetId: id,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: patch,
    });
    return toChannel(row);
  }

  async listChannels(): Promise<NotificationChannel[]> {
    const rows = await this.db
      .select()
      .from(notificationChannels)
      .orderBy(notificationChannels.createdAt)
      .limit(100);
    return rows.map(toChannel);
  }

  async deliveries(limit = 50): Promise<NotificationDelivery[]> {
    const rows = await this.db
      .select()
      .from(notificationDeliveries)
      .orderBy(desc(notificationDeliveries.attemptedAt))
      .limit(limit);
    return rows.map(toDelivery);
  }

  // ---- delivery ---------------------------------------------------------------------------
  private async deliver(
    channel: ChannelRow,
    event: WebhookPayload['event'],
    condition: PlatformCondition,
    now: Date,
  ): Promise<{ ok: boolean; httpStatus: number | null; error: string | null }> {
    const payload: WebhookPayload = {
      event,
      condition,
      platform: { service: 'noc-api', version: this.opts.version },
      at: now.toISOString(),
    };
    const body = JSON.stringify(payload);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 5000);
    let ok = false;
    let httpStatus: number | null = null;
    let error: string | null = null;
    try {
      const res = await (this.opts.fetchImpl ?? fetch)(channel.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'user-agent': 'noc-api/notifications',
          'x-noc-event': event,
          'x-noc-timestamp': now.toISOString(),
          'x-noc-signature': signWebhook(channel.secret, body),
        },
        body,
        signal: ctrl.signal,
        redirect: 'manual',
      });
      httpStatus = res.status;
      ok = res.status >= 200 && res.status < 300;
      if (!ok) error = `HTTP ${res.status}`;
    } catch (err) {
      error = (err instanceof Error ? err.message : String(err)).slice(0, 512);
    } finally {
      clearTimeout(timer);
    }
    await this.db.insert(notificationDeliveries).values({
      channelId: channel.id,
      conditionId: condition.id,
      event,
      severity: condition.severity,
      status: ok ? 'sent' : 'failed',
      httpStatus,
      error,
      attemptedAt: now,
    });
    await this.db
      .update(notificationChannels)
      .set({ lastAttemptAt: now, lastStatus: ok ? 'sent' : 'failed', lastError: error })
      .where(eq(notificationChannels.id, channel.id));
    if (!ok)
      this.opts.logger.warn(
        { channel: channel.name, event, condition: condition.id, httpStatus, error },
        'webhook delivery failed',
      );
    return { ok, httpStatus, error };
  }

  async testChannel(id: string, actor: Actor): Promise<NotificationDelivery> {
    const [channel] = await this.db
      .select()
      .from(notificationChannels)
      .where(eq(notificationChannels.id, id))
      .limit(1);
    if (!channel) throw new HTTPException(404, { message: 'Channel not found' });
    const now = new Date();
    await this.deliver(
      channel,
      'test',
      {
        id: 'test',
        severity: 'info',
        title: 'Test notification',
        detail: `Requested by ${actor.label}; nothing is wrong`,
        count: 0,
        link: null,
      },
      now,
    );
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'notifications.channel_test',
      outcome: 'success',
      targetType: 'notification_channel',
      targetId: id,
      requestId: actor.requestId,
      sourceIp: actor.ip,
    });
    const [d] = await this.db
      .select()
      .from(notificationDeliveries)
      .where(eq(notificationDeliveries.channelId, id))
      .orderBy(desc(notificationDeliveries.attemptedAt))
      .limit(1);
    return toDelivery(d!);
  }

  /**
   * One notification cycle. Per enabled channel: raise new or changed conditions at or above
   * its minimum severity, remind about still-active ones after the quiet period, resolve the
   * ones that disappeared. A failed delivery leaves the state untouched so it is retried.
   */
  async notify(now = new Date()): Promise<{ raised: number; resolved: number; failed: number }> {
    const channels = await this.db
      .select()
      .from(notificationChannels)
      .where(eq(notificationChannels.enabled, true));
    const out = { raised: 0, resolved: 0, failed: 0 };
    if (channels.length === 0) return out;
    const { conditions } = await this.conditions(now);
    const remindMs = this.opts.remindHours * 3_600_000;
    for (const ch of channels) {
      const relevant = conditions.filter(
        (c) =>
          CONDITION_SEVERITY_RANK[c.severity] >=
          CONDITION_SEVERITY_RANK[ch.minSeverity as ConditionSeverity],
      );
      const states = await this.db
        .select()
        .from(notificationStates)
        .where(eq(notificationStates.channelId, ch.id));
      const byId = new Map(states.map((s) => [s.conditionId, s]));
      for (const c of relevant) {
        const fp = conditionFingerprint(c);
        const st = byId.get(c.id);
        const due =
          !st ||
          !st.active ||
          st.fingerprint !== fp ||
          st.lastSentAt === null ||
          now.getTime() - st.lastSentAt.getTime() >= remindMs;
        if (!due) continue;
        const r = await this.deliver(ch, 'raised', c, now);
        if (!r.ok) {
          out.failed++;
          continue;
        }
        out.raised++;
        await this.db
          .insert(notificationStates)
          .values({
            channelId: ch.id,
            conditionId: c.id,
            fingerprint: fp,
            active: true,
            lastSentAt: now,
            updatedAt: now,
          })
          .onConflictDoUpdate({
            target: [notificationStates.channelId, notificationStates.conditionId],
            set: { fingerprint: fp, active: true, lastSentAt: now, updatedAt: now },
          });
      }
      const present = new Set(relevant.map((c) => c.id));
      const gone = states.filter((s) => s.active && !present.has(s.conditionId));
      for (const s of gone) {
        const r = await this.deliver(
          ch,
          'resolved',
          {
            id: s.conditionId,
            severity: 'info',
            title: 'Condition resolved',
            detail: `${s.conditionId} is no longer present`,
            count: 0,
            link: null,
          },
          now,
        );
        if (!r.ok) {
          out.failed++;
          continue;
        }
        out.resolved++;
        await this.db
          .update(notificationStates)
          .set({ active: false, lastSentAt: now, updatedAt: now })
          .where(
            and(
              eq(notificationStates.channelId, ch.id),
              inArray(notificationStates.conditionId, [s.conditionId]),
            ),
          );
      }
    }
    return out;
  }
}

export class NotificationScheduler {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly svc: OperationsService,
    private readonly opts: { intervalSeconds: number; logger: Logger },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.intervalSeconds * 1000);
    this.timer.unref();
    this.opts.logger.info(
      { intervalSeconds: this.opts.intervalSeconds },
      'notification scheduler started',
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
      const r = await this.svc.notify();
      if (r.raised || r.resolved || r.failed) this.opts.logger.info(r, 'notifications cycle');
    } catch (err) {
      this.opts.logger.error({ err }, 'notifications cycle failed');
    } finally {
      this.running = false;
    }
  }
}
