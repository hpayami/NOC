import { HTTPException } from 'hono/http-exception';
import type { Logger } from 'pino';
import { and, desc, eq, inArray, sql, type SQL } from 'drizzle-orm';
import {
  checkApproval,
  checkIpsContinuation,
  checkIpsEnable,
  publicCidrs,
  requiredApprovals,
  type IpsAckRequest,
  type IpsDisableCause,
  type IpsPolicy,
  type Permission,
  type ProposeIpsPolicyRequest,
  type SensorIpsDirective,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { approvals, detectionRules, ipsPolicies, sensorHealth, sensors } from '../db/schema';

export interface Actor {
  userId: string;
  email: string;
  permissions: ReadonlySet<Permission>;
  requestId: string | null;
  ip: string | null;
}

type PolicyRow = typeof ipsPolicies.$inferSelect;
type ApprovalRow = typeof approvals.$inferSelect;

const toPolicy = (p: PolicyRow, sensorName: string, aps: ApprovalRow[]): IpsPolicy => ({
  id: p.id,
  name: p.name,
  sensorId: p.sensorId,
  sensorName,
  mode: p.mode,
  action: p.action,
  protectedCidrs: p.protectedCidrs,
  excludedCidrs: p.excludedCidrs,
  ruleIds: p.ruleIds,
  status: p.status,
  version: p.version,
  justification: p.justification,
  rollbackPlan: p.rollbackPlan,
  proposedBy: p.proposedBy,
  requiredApprovals: p.requiredApprovals,
  approvals: aps.map((a) => ({
    approverId: a.approverId,
    decision: a.decision,
    justification: a.justification,
    decidedAt: a.decidedAt.toISOString(),
  })),
  approvalsGranted: aps.filter((a) => a.decision === 'approved').length,
  enabledBy: p.enabledBy,
  enabledAt: p.enabledAt?.toISOString() ?? null,
  expiresAt: p.expiresAt?.toISOString() ?? null,
  disabledBy: p.disabledBy,
  disabledAt: p.disabledAt?.toISOString() ?? null,
  disableReason: p.disableReason,
  disableCause: (p.disableCause as IpsPolicy['disableCause']) ?? null,
  applyState: p.applyState,
  appliedVersion: p.appliedVersion,
  appliedAt: p.appliedAt?.toISOString() ?? null,
  applyDetail: p.applyDetail,
  createdAt: p.createdAt.toISOString(),
  updatedAt: p.updatedAt.toISOString(),
});

/**
 * Inline-prevention policy plane. The management plane never flips a sensor inline on its own:
 * a policy needs two independent approvals, a healthy inline-capable sensor, a person holding
 * `ips.enable` who did not approve it, and a TTL after which the sensor falls back to detect-only.
 */
export class IpsService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  private auditOf(
    actor: Actor | null,
    action: string,
    targetId: string,
    metadata: Record<string, unknown>,
    outcome: 'success' | 'denied' | 'failure' = 'success',
  ) {
    return {
      actorId: actor?.userId ?? null,
      actorLabel: actor?.email ?? 'system:ips',
      action,
      outcome,
      targetType: 'ips_policy',
      targetId,
      requestId: actor?.requestId ?? null,
      sourceIp: actor?.ip ?? null,
      metadata,
    };
  }

  private approvalsOf(id: string, exec: Db | DbTx = this.db) {
    return exec
      .select()
      .from(approvals)
      .where(and(eq(approvals.subjectType, 'ips_policy'), eq(approvals.subjectId, id)))
      .orderBy(approvals.decidedAt);
  }

  private async lock(tx: DbTx, id: string): Promise<PolicyRow> {
    const [row] = await tx
      .select()
      .from(ipsPolicies)
      .where(eq(ipsPolicies.id, id))
      .limit(1)
      .for('update');
    if (!row) throw new HTTPException(404, { message: 'Policy not found' });
    return row;
  }

  private async sensorName(id: string): Promise<string> {
    const [s] = await this.db
      .select({ name: sensors.name })
      .from(sensors)
      .where(eq(sensors.id, id))
      .limit(1);
    return s?.name ?? 'unknown';
  }

  async propose(input: ProposeIpsPolicyRequest, actor: Actor): Promise<IpsPolicy> {
    const [sensor] = await this.db
      .select()
      .from(sensors)
      .where(eq(sensors.id, input.sensorId))
      .limit(1);
    if (!sensor) throw new HTTPException(404, { message: 'Sensor not found' });
    if (sensor.kind !== 'suricata')
      throw new HTTPException(409, { message: 'Only Suricata sensors can run inline policies' });
    const pub = publicCidrs(input.protectedCidrs);
    if (pub.length)
      throw new HTTPException(400, {
        message: `Protected ranges must be non-public: ${pub.join(', ')}`,
      });
    const rules = await this.db
      .select({
        id: detectionRules.id,
        lifecycle: detectionRules.lifecycle,
        enabled: detectionRules.enabled,
      })
      .from(detectionRules)
      .where(inArray(detectionRules.id, input.ruleIds));
    const found = new Map(rules.map((r) => [r.id, r]));
    for (const id of input.ruleIds) {
      const r = found.get(id);
      if (!r) throw new HTTPException(404, { message: `Rule ${id} not found` });
      if (!r.enabled || (r.lifecycle !== 'validated' && r.lifecycle !== 'deployed'))
        throw new HTTPException(409, {
          message: `Rule ${id} is ${r.enabled ? r.lifecycle : 'disabled'}; only enabled validated/deployed rules may drop traffic`,
        });
    }
    const required = requiredApprovals('enable_inline_prevention');
    const row = await this.db.transaction(async (tx) => {
      const [row] = await tx
        .insert(ipsPolicies)
        .values({
          name: input.name,
          sensorId: input.sensorId,
          mode: input.mode,
          action: input.action,
          protectedCidrs: input.protectedCidrs,
          excludedCidrs: input.excludedCidrs,
          ruleIds: input.ruleIds,
          justification: input.justification,
          rollbackPlan: input.rollbackPlan,
          proposedBy: actor.userId,
          requiredApprovals: required,
        })
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'ips.propose', row!.id, {
          sensorId: input.sensorId,
          mode: input.mode,
          rules: input.ruleIds.length,
          protectedCidrs: input.protectedCidrs,
        }),
        tx,
      );
      return row!;
    });
    return toPolicy(row, sensor.name, []);
  }

  async decide(
    id: string,
    decision: 'approved' | 'rejected',
    justification: string,
    actor: Actor,
  ): Promise<IpsPolicy> {
    const now = new Date();
    const [peek] = await this.db.select().from(ipsPolicies).where(eq(ipsPolicies.id, id)).limit(1);
    if (!peek) throw new HTTPException(404, { message: 'Policy not found' });
    const prior = await this.approvalsOf(id);
    const check = checkApproval({
      kind: 'enable_inline_prevention',
      status: peek.status,
      proposedBy: peek.proposedBy,
      approverId: actor.userId,
      approverPermissions: actor.permissions,
      priorApproverIds: prior.map((p) => p.approverId),
      expiresAt: null,
      now,
    });
    const action = decision === 'approved' ? 'ips.approve' : 'ips.reject';
    if (!check.ok) {
      const denied = check.code === 'forbidden' || check.code === 'self_approval';
      await this.audit.record(
        this.auditOf(actor, action, id, { code: check.code }, denied ? 'denied' : 'failure'),
      );
      throw new HTTPException(denied ? 403 : 409, { message: check.message });
    }
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status !== 'pending_approval')
        throw new HTTPException(409, { message: 'Policy is not awaiting approval' });
      await tx.insert(approvals).values({
        subjectType: 'ips_policy',
        subjectId: id,
        approverId: actor.userId,
        decision,
        justification,
        decidedAt: now,
      });
      const all = await this.approvalsOf(id, tx);
      const granted = all.filter((p) => p.decision === 'approved').length;
      const status =
        decision === 'rejected'
          ? 'rejected'
          : granted >= cur.requiredApprovals
            ? 'approved'
            : 'pending_approval';
      const [updated] = await tx
        .update(ipsPolicies)
        .set({ status, updatedAt: now })
        .where(eq(ipsPolicies.id, id))
        .returning();
      await this.audit.record(
        this.auditOf(actor, action, id, {
          granted,
          required: cur.requiredApprovals,
          status,
          justification,
        }),
        tx,
      );
      return updated!;
    });
    return toPolicy(row, await this.sensorName(row.sensorId), await this.approvalsOf(id));
  }

  async enable(id: string, enabledForHours: number, actor: Actor): Promise<IpsPolicy> {
    const now = new Date();
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      const [sensor] = await tx
        .select()
        .from(sensors)
        .where(eq(sensors.id, cur.sensorId))
        .limit(1)
        .for('update');
      if (!sensor) throw new HTTPException(404, { message: 'Sensor not found' });
      const [latest] = await tx
        .select({ state: sensorHealth.state })
        .from(sensorHealth)
        .where(eq(sensorHealth.sensorId, sensor.id))
        .orderBy(desc(sensorHealth.recordedAt))
        .limit(1);
      const [other] = await tx
        .select({ id: ipsPolicies.id })
        .from(ipsPolicies)
        .where(and(eq(ipsPolicies.sensorId, sensor.id), eq(ipsPolicies.status, 'enabled')))
        .limit(1);
      const aps = await this.approvalsOf(id, tx);
      const check = checkIpsEnable({
        status: cur.status,
        requiredApprovals: cur.requiredApprovals,
        approverIds: aps.filter((a) => a.decision === 'approved').map((a) => a.approverId),
        enablerId: actor.userId,
        sensor: {
          enabled: sensor.enabled,
          inlineCapable: sensor.inlineCapable,
          kind: sensor.kind,
          lastHeartbeatAt: sensor.lastHeartbeatAt,
          latestHealthState: latest?.state ?? null,
          hasEnabledPolicy: Boolean(other),
        },
        enabledForHours,
        now,
      });
      if (!check.ok) return { refusal: check, cur };
      const [updated] = await tx
        .update(ipsPolicies)
        .set({
          status: 'enabled',
          version: cur.version + 1,
          enabledBy: actor.userId,
          enabledAt: now,
          expiresAt: new Date(now.getTime() + enabledForHours * 3_600_000),
          disabledBy: null,
          disabledAt: null,
          disableReason: null,
          disableCause: null,
          applyState: 'pending',
          updatedAt: now,
        })
        .where(eq(ipsPolicies.id, id))
        .returning();
      await tx.update(sensors).set({ mode: 'inline_prevention' }).where(eq(sensors.id, sensor.id));
      await this.audit.record(
        this.auditOf(actor, 'ips.enable', id, {
          sensorId: sensor.id,
          mode: cur.mode,
          enabledForHours,
          expiresAt: updated!.expiresAt?.toISOString(),
          version: updated!.version,
        }),
        tx,
      );
      return { refusal: null, cur: updated! };
    });
    if (row.refusal) {
      await this.audit.record(
        this.auditOf(
          actor,
          'ips.enable',
          id,
          { code: row.refusal.code, status: row.cur.status },
          row.refusal.code === 'sod' ? 'denied' : 'failure',
        ),
      );
      throw new HTTPException(row.refusal.code === 'sod' ? 403 : 409, {
        message: row.refusal.message,
      });
    }
    return toPolicy(row.cur, await this.sensorName(row.cur.sensorId), await this.approvalsOf(id));
  }

  /** Kill switch: anyone holding ips.enable or ips.approve may disable; never needs approval. */
  async disable(
    id: string,
    reason: string,
    actor: Actor | null,
    cause: IpsDisableCause = 'manual',
  ): Promise<IpsPolicy> {
    const now = new Date();
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status !== 'enabled')
        throw new HTTPException(409, { message: `Policy is ${cur.status}, not enabled` });
      const status = cause === 'expired' ? 'expired' : 'disabled';
      const [updated] = await tx
        .update(ipsPolicies)
        .set({
          status,
          version: cur.version + 1,
          disabledBy: actor?.userId ?? null,
          disabledAt: now,
          disableReason: reason,
          disableCause: cause,
          applyState: 'pending',
          updatedAt: now,
        })
        .where(eq(ipsPolicies.id, id))
        .returning();
      await tx.update(sensors).set({ mode: 'out_of_band' }).where(eq(sensors.id, cur.sensorId));
      const action =
        cause === 'expired'
          ? 'ips.expire'
          : cause === 'sensor_unhealthy'
            ? 'ips.auto_disable'
            : 'ips.disable';
      await this.audit.record(
        this.auditOf(actor, action, id, {
          sensorId: cur.sensorId,
          reason,
          cause,
          version: updated!.version,
        }),
        tx,
      );
      return updated!;
    });
    return toPolicy(row, await this.sensorName(row.sensorId), await this.approvalsOf(id));
  }

  /**
   * Watchdog: every enabled policy is re-checked against the continuation gate (sensor enabled,
   * inline-capable, heartbeating within the window, last health `healthy`). A sensor that stops
   * qualifying is returned to detect-only immediately, audited as `system:ips`. Runs on every
   * sensor heartbeat, on every directive fetch and policy list, and on the scheduler.
   */
  async enforceSensorHealth(now = new Date(), sensorId?: string): Promise<number> {
    const enabled = await this.db
      .select({ policyId: ipsPolicies.id, sensor: sensors })
      .from(ipsPolicies)
      .innerJoin(sensors, eq(sensors.id, ipsPolicies.sensorId))
      .where(
        and(
          eq(ipsPolicies.status, 'enabled'),
          sensorId ? eq(ipsPolicies.sensorId, sensorId) : undefined,
        ),
      );
    let dropped = 0;
    for (const e of enabled) {
      const [latest] = await this.db
        .select({ state: sensorHealth.state })
        .from(sensorHealth)
        .where(eq(sensorHealth.sensorId, e.sensor.id))
        .orderBy(desc(sensorHealth.recordedAt))
        .limit(1);
      const check = checkIpsContinuation({
        sensor: {
          enabled: e.sensor.enabled,
          inlineCapable: e.sensor.inlineCapable,
          kind: e.sensor.kind,
          lastHeartbeatAt: e.sensor.lastHeartbeatAt,
          latestHealthState: latest?.state ?? null,
        },
        now,
      });
      if (check.ok) continue;
      await this.disable(
        e.policyId,
        `Sensor no longer qualifies for inline prevention (${check.code}: ${check.message}); detect-only enforced automatically`,
        null,
        'sensor_unhealthy',
      ).catch(() => undefined);
      dropped++;
    }
    return dropped;
  }

  /** TTL expiry plus the sensor-health watchdog, in that order. */
  async enforce(now = new Date()): Promise<{ expired: number; autoDisabled: number }> {
    const expired = await this.expireDue(now);
    const autoDisabled = await this.enforceSensorHealth(now);
    return { expired, autoDisabled };
  }

  /** Expires every enabled policy past its TTL; sensors fall back to detect-only on their next fetch. */
  async expireDue(now = new Date()): Promise<number> {
    const due = await this.db
      .select({ id: ipsPolicies.id })
      .from(ipsPolicies)
      .where(
        and(
          eq(ipsPolicies.status, 'enabled'),
          sql`${ipsPolicies.expiresAt} <= ${now.toISOString()}::timestamptz`,
        ),
      );
    for (const d of due)
      await this.disable(d.id, 'TTL reached; sensor returns to detect-only', null, 'expired').catch(
        () => undefined,
      );
    return due.length;
  }

  /** What a sensor should run right now. Default is detect-only and fail-open. */
  async directiveFor(sensorId: string, now = new Date()): Promise<SensorIpsDirective> {
    await this.enforce(now);
    const [p] = await this.db
      .select()
      .from(ipsPolicies)
      .where(and(eq(ipsPolicies.sensorId, sensorId), eq(ipsPolicies.status, 'enabled')))
      .limit(1);
    const issuedAt = now.toISOString();
    if (!p)
      return {
        mode: 'ids',
        policyId: null,
        version: 0,
        action: 'drop',
        protectedCidrs: [],
        excludedCidrs: [],
        ruleRefs: [],
        expiresAt: null,
        failOpen: true,
        issuedAt,
      };
    const refs = p.ruleIds.length
      ? await this.db
          .select({ ext: detectionRules.externalId })
          .from(detectionRules)
          .where(and(inArray(detectionRules.id, p.ruleIds), eq(detectionRules.enabled, true)))
      : [];
    return {
      mode: p.mode,
      policyId: p.id,
      version: p.version,
      action: p.action,
      protectedCidrs: p.protectedCidrs,
      excludedCidrs: p.excludedCidrs,
      ruleRefs: refs.map((r) => r.ext),
      expiresAt: p.expiresAt?.toISOString() ?? null,
      failOpen: true,
      issuedAt,
    };
  }

  /** Sensor acknowledges the version it applied (or failed to apply). */
  async ack(sensorId: string, body: IpsAckRequest): Promise<void> {
    const now = new Date();
    const target = body.policyId
      ? await this.db
          .select()
          .from(ipsPolicies)
          .where(and(eq(ipsPolicies.id, body.policyId), eq(ipsPolicies.sensorId, sensorId)))
          .limit(1)
      : await this.db
          .select()
          .from(ipsPolicies)
          .where(
            and(
              eq(ipsPolicies.sensorId, sensorId),
              inArray(ipsPolicies.status, ['disabled', 'expired']),
            ),
          )
          .orderBy(desc(ipsPolicies.updatedAt))
          .limit(1);
    const p = target[0];
    if (!p) return;
    await this.db
      .update(ipsPolicies)
      .set({
        applyState: body.applied ? 'applied' : 'failed',
        appliedVersion: body.version,
        appliedAt: now,
        applyDetail: body.detail,
        updatedAt: now,
      })
      .where(eq(ipsPolicies.id, p.id));
    if (!body.applied)
      await this.audit.record(
        this.auditOf(
          null,
          'ips.apply_failed',
          p.id,
          { sensorId, version: body.version, detail: body.detail },
          'failure',
        ),
      );
  }

  async get(id: string): Promise<IpsPolicy> {
    const [row] = await this.db.select().from(ipsPolicies).where(eq(ipsPolicies.id, id)).limit(1);
    if (!row) throw new HTTPException(404, { message: 'Policy not found' });
    return toPolicy(row, await this.sensorName(row.sensorId), await this.approvalsOf(id));
  }

  async list(conds: SQL[], limit: number): Promise<IpsPolicy[]> {
    const rows = await this.db
      .select({ policy: ipsPolicies, sensorName: sensors.name })
      .from(ipsPolicies)
      .innerJoin(sensors, eq(sensors.id, ipsPolicies.sensorId))
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(ipsPolicies.createdAt))
      .limit(limit);
    if (!rows.length) return [];
    const aps = await this.db
      .select()
      .from(approvals)
      .where(
        and(
          eq(approvals.subjectType, 'ips_policy'),
          inArray(
            approvals.subjectId,
            rows.map((r) => r.policy.id),
          ),
        ),
      )
      .orderBy(approvals.decidedAt);
    return rows.map((r) =>
      toPolicy(
        r.policy,
        r.sensorName,
        aps.filter((a) => a.subjectId === r.policy.id),
      ),
    );
  }

  async enabledSummary(): Promise<
    Array<{ sensorName: string; mode: string; expiresAt: Date | null; applyState: string }>
  > {
    const rows = await this.db
      .select({
        sensorName: sensors.name,
        mode: ipsPolicies.mode,
        expiresAt: ipsPolicies.expiresAt,
        applyState: ipsPolicies.applyState,
      })
      .from(ipsPolicies)
      .innerJoin(sensors, eq(sensors.id, ipsPolicies.sensorId))
      .where(eq(ipsPolicies.status, 'enabled'));
    return rows;
  }
}

/** Periodic safety net for the continuation gate: a silent sensor sends no heartbeat to trigger it. */
export class IpsWatchdog {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly svc: IpsService,
    private readonly opts: { intervalSeconds: number; logger: Logger },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.intervalSeconds * 1000);
    this.timer.unref();
    this.opts.logger.info({ intervalSeconds: this.opts.intervalSeconds }, 'ips watchdog started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<{ expired: number; autoDisabled: number }> {
    if (this.running) return { expired: 0, autoDisabled: 0 };
    this.running = true;
    try {
      const r = await this.svc.enforce();
      if (r.expired || r.autoDisabled)
        this.opts.logger.warn(r, 'ips watchdog: sensors returned to detect-only');
      return r;
    } catch (err) {
      this.opts.logger.error({ err }, 'ips watchdog tick failed');
      return { expired: 0, autoDisabled: 0 };
    } finally {
      this.running = false;
    }
  }
}
