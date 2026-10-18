import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, inArray, isNotNull, sql, type SQL } from 'drizzle-orm';
import {
  CLOSED_ALERT_STATUSES,
  allowedNextStates,
  validateAlertTransition,
  validateIncidentTransition,
  type CreateIncidentRequest,
  type IncidentDetail,
  type IncidentStats,
  type IncidentSummary,
  type IncidentTimelineEntry,
  type IncidentUpdateRequest,
  type Permission,
  IncidentStatusValues,
  SeverityValues,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { alerts, incidentEvents, incidents, securityEvents } from '../db/schema';
import type { AlertBus } from '../events/bus';
import { toAlert } from '../routes/alerts';

export interface Actor {
  userId: string;
  email: string;
  permissions: ReadonlySet<Permission>;
  requestId: string | null;
  ip: string | null;
}

type IncidentRow = typeof incidents.$inferSelect;

/** Monotonic timestamps within one transaction so timeline order is deterministic. */
const stamper = () => {
  const base = Date.now();
  let n = 0;
  return () => new Date(base + n++);
};

export const toIncident = (i: IncidentRow, alertCount: number): IncidentSummary => ({
  id: i.id,
  title: i.title,
  type: i.type,
  status: i.status,
  severity: i.severity,
  assigneeId: i.assigneeId,
  commanderId: i.commanderId,
  summary: i.summary,
  openedAt: i.openedAt.toISOString(),
  closedAt: i.closedAt?.toISOString() ?? null,
  closureReason: i.closureReason,
  openedBy: i.openedBy,
  updatedAt: i.updatedAt.toISOString(),
  alertCount,
});

const toTimeline = (e: typeof incidentEvents.$inferSelect): IncidentTimelineEntry => ({
  id: e.id,
  occurredAt: e.occurredAt.toISOString(),
  actorId: e.actorId,
  kind: e.kind as IncidentTimelineEntry['kind'],
  fromStatus: e.fromStatus,
  toStatus: e.toStatus,
  note: e.note,
  payload: e.payload,
});

/**
 * Incident lifecycle. Every mutation runs in one transaction with a row lock on the incident,
 * appends a timeline entry and an audit event; alert links are the only cross-table effect.
 */
export class IncidentService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly bus: AlertBus,
  ) {}

  private auditOf(
    actor: Actor,
    action: string,
    targetId: string,
    metadata: Record<string, unknown>,
  ) {
    return {
      actorId: actor.userId,
      actorLabel: actor.email,
      action,
      outcome: 'success' as const,
      targetType: 'incident',
      targetId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata,
    };
  }

  private async lock(tx: DbTx, id: string): Promise<IncidentRow> {
    const [row] = await tx
      .select()
      .from(incidents)
      .where(eq(incidents.id, id))
      .limit(1)
      .for('update');
    if (!row) throw new HTTPException(404, { message: 'Incident not found' });
    return row;
  }

  /**
   * Attaches alerts to an incident. Open alerts are escalated when the triage state machine
   * allows it; closed ones are linked as evidence without changing state. An alert already
   * attached to a different incident is refused (one owner per alert).
   */
  private async attachAlerts(
    tx: DbTx,
    incident: IncidentRow,
    alertIds: string[],
    actor: Actor,
    at: () => Date,
  ): Promise<Array<{ id: string; severity: string; title: string }>> {
    if (alertIds.length === 0) return [];
    const rows = await tx.select().from(alerts).where(inArray(alerts.id, alertIds)).for('update');
    const found = new Set(rows.map((r) => r.id));
    const missing = alertIds.find((id) => !found.has(id));
    if (missing) throw new HTTPException(404, { message: `Alert ${missing} not found` });
    const foreign = rows.find((r) => r.incidentId && r.incidentId !== incident.id);
    if (foreign)
      throw new HTTPException(409, {
        message: `Alert ${foreign.id} is already attached to incident ${foreign.incidentId}`,
      });
    const escalated: Array<{ id: string; severity: string; title: string }> = [];
    for (const a of rows) {
      if (a.incidentId === incident.id) continue;
      const t = validateAlertTransition(a.status, 'escalate');
      await tx
        .update(alerts)
        .set({ incidentId: incident.id, status: t.ok ? t.to : a.status, updatedAt: new Date() })
        .where(eq(alerts.id, a.id));
      if (a.lastEventId)
        await tx
          .update(securityEvents)
          .set({ incidentId: incident.id })
          .where(eq(securityEvents.id, a.lastEventId));
      await tx.insert(incidentEvents).values({
        incidentId: incident.id,
        occurredAt: at(),
        actorId: actor.userId,
        kind: 'alert_linked',
        payload: { alertId: a.id, title: a.title, escalated: t.ok, fromStatus: a.status },
      });
      if (t.ok) escalated.push({ id: a.id, severity: a.severity, title: a.title });
    }
    return escalated;
  }

  private publishEscalated(list: Array<{ id: string; severity: string; title: string }>) {
    const at = new Date().toISOString();
    for (const a of list)
      this.bus.publish({
        kind: 'triaged',
        alertId: a.id,
        severity: a.severity as IncidentSummary['severity'],
        title: a.title,
        at,
      });
  }

  async create(input: CreateIncidentRequest, actor: Actor): Promise<IncidentSummary> {
    const { row, escalated } = await this.db.transaction(async (tx) => {
      const at = stamper();
      const [row] = await tx
        .insert(incidents)
        .values({
          title: input.title,
          type: input.type,
          severity: input.severity,
          summary: input.summary,
          openedBy: actor.userId,
          assigneeId: actor.userId,
        })
        .returning();
      await tx.insert(incidentEvents).values({
        incidentId: row!.id,
        occurredAt: at(),
        actorId: actor.userId,
        kind: 'opened',
        toStatus: 'new',
        payload: { type: input.type, severity: input.severity, alertIds: input.alertIds },
      });
      const escalated = await this.attachAlerts(tx, row!, input.alertIds, actor, at);
      await this.audit.record(
        this.auditOf(actor, 'incidents.create', row!.id, {
          type: input.type,
          severity: input.severity,
          alerts: input.alertIds.length,
        }),
        tx,
      );
      return { row: row!, escalated };
    });
    this.publishEscalated(escalated);
    return toIncident(row, input.alertIds.length);
  }

  async transition(
    id: string,
    to: IncidentSummary['status'],
    reason: string | undefined,
    actor: Actor,
  ) {
    // Permission denial is audited before the transaction: an audit row written inside a
    // transaction that then throws would be rolled back with it.
    const [peek] = await this.db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
    if (!peek) throw new HTTPException(404, { message: 'Incident not found' });
    const pre = validateIncidentTransition({ type: peek.type, from: peek.status, to, reason });
    if (pre.ok && pre.requiresPermission && !actor.permissions.has(pre.requiresPermission)) {
      await this.audit.record({
        ...this.auditOf(actor, 'incidents.transition', id, { from: peek.status, to }),
        outcome: 'denied',
      });
      throw new HTTPException(403, { message: `Transition requires ${pre.requiresPermission}` });
    }
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      const t = validateIncidentTransition({ type: cur.type, from: cur.status, to, reason });
      if (!t.ok) throw new HTTPException(409, { message: t.message });
      // Re-checked under the row lock in case the state moved between the peek and the lock.
      if (t.requiresPermission && !actor.permissions.has(t.requiresPermission))
        throw new HTTPException(403, { message: `Transition requires ${t.requiresPermission}` });
      const now = new Date();
      const closing = to === 'closed';
      const [updated] = await tx
        .update(incidents)
        .set({
          status: to,
          closedAt: closing ? now : cur.status === 'closed' ? null : cur.closedAt,
          closureReason: closing
            ? (reason ?? null)
            : cur.status === 'closed'
              ? null
              : cur.closureReason,
          updatedAt: now,
        })
        .where(eq(incidents.id, id))
        .returning();
      await tx.insert(incidentEvents).values({
        incidentId: id,
        actorId: actor.userId,
        kind: 'transition',
        fromStatus: cur.status,
        toStatus: to,
        note: reason ?? null,
        payload: { deviation: t.deviation },
      });
      await this.audit.record(
        this.auditOf(actor, 'incidents.transition', id, {
          from: cur.status,
          to,
          deviation: t.deviation,
          reason: reason ?? null,
        }),
        tx,
      );
      return updated!;
    });
    return toIncident(row, await this.alertCount(id));
  }

  async addNote(id: string, note: string, actor: Actor): Promise<IncidentTimelineEntry> {
    return this.db.transaction(async (tx) => {
      await this.lock(tx, id);
      const [e] = await tx
        .insert(incidentEvents)
        .values({ incidentId: id, actorId: actor.userId, kind: 'note', note })
        .returning();
      await tx.update(incidents).set({ updatedAt: new Date() }).where(eq(incidents.id, id));
      await this.audit.record(
        this.auditOf(actor, 'incidents.note', id, { length: note.length }),
        tx,
      );
      return toTimeline(e!);
    });
  }

  async update(id: string, patch: IncidentUpdateRequest, actor: Actor): Promise<IncidentSummary> {
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status === 'closed')
        throw new HTTPException(409, { message: 'Closed incidents are read-only; reopen first' });
      const set: Partial<typeof incidents.$inferInsert> = { updatedAt: new Date() };
      const entries: Array<typeof incidentEvents.$inferInsert> = [];
      if (patch.assigneeId !== undefined || patch.commanderId !== undefined) {
        if (patch.assigneeId !== undefined) set.assigneeId = patch.assigneeId;
        if (patch.commanderId !== undefined) set.commanderId = patch.commanderId;
        entries.push({
          incidentId: id,
          actorId: actor.userId,
          kind: 'assignment',
          payload: {
            assigneeId: patch.assigneeId ?? cur.assigneeId,
            commanderId: patch.commanderId ?? cur.commanderId,
          },
        });
      }
      if (patch.severity !== undefined && patch.severity !== cur.severity) {
        set.severity = patch.severity;
        entries.push({
          incidentId: id,
          actorId: actor.userId,
          kind: 'severity_changed',
          payload: { from: cur.severity, to: patch.severity },
        });
      }
      if (patch.title !== undefined || patch.summary !== undefined) {
        if (patch.title !== undefined) set.title = patch.title;
        if (patch.summary !== undefined) set.summary = patch.summary;
        entries.push({
          incidentId: id,
          actorId: actor.userId,
          kind: 'updated',
          payload: {
            fields: ['title', 'summary'].filter(
              (f) => patch[f as 'title' | 'summary'] !== undefined,
            ),
          },
        });
      }
      const [updated] = await tx.update(incidents).set(set).where(eq(incidents.id, id)).returning();
      const at = stamper();
      if (entries.length)
        await tx.insert(incidentEvents).values(entries.map((e) => ({ ...e, occurredAt: at() })));
      await this.audit.record(
        this.auditOf(actor, 'incidents.update', id, { fields: Object.keys(patch) }),
        tx,
      );
      return updated!;
    });
    return toIncident(row, await this.alertCount(id));
  }

  async linkAlerts(id: string, alertIds: string[], actor: Actor): Promise<IncidentSummary> {
    const { row, escalated } = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status === 'closed')
        throw new HTTPException(409, { message: 'Cannot attach alerts to a closed incident' });
      const escalated = await this.attachAlerts(tx, cur, alertIds, actor, stamper());
      await tx.update(incidents).set({ updatedAt: new Date() }).where(eq(incidents.id, id));
      await this.audit.record(
        this.auditOf(actor, 'incidents.link_alerts', id, { alerts: alertIds }),
        tx,
      );
      return { row: cur, escalated };
    });
    this.publishEscalated(escalated);
    return toIncident(row, await this.alertCount(id));
  }

  async unlinkAlert(id: string, alertId: string, actor: Actor): Promise<void> {
    await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status === 'closed')
        throw new HTTPException(409, { message: 'Cannot detach alerts from a closed incident' });
      const [a] = await tx
        .update(alerts)
        .set({ incidentId: null, updatedAt: new Date() })
        .where(and(eq(alerts.id, alertId), eq(alerts.incidentId, id)))
        .returning({ id: alerts.id, title: alerts.title });
      if (!a) throw new HTTPException(404, { message: 'Alert is not attached to this incident' });
      await tx
        .update(securityEvents)
        .set({ incidentId: null })
        .where(eq(securityEvents.incidentId, id));
      await tx.insert(incidentEvents).values({
        incidentId: id,
        actorId: actor.userId,
        kind: 'alert_unlinked',
        payload: { alertId, title: a.title },
      });
      await this.audit.record(this.auditOf(actor, 'incidents.unlink_alert', id, { alertId }), tx);
    });
  }

  private async alertCount(id: string): Promise<number> {
    const [r] = await this.db.select({ n: count() }).from(alerts).where(eq(alerts.incidentId, id));
    return r?.n ?? 0;
  }

  async detail(id: string): Promise<IncidentDetail> {
    const [row] = await this.db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
    if (!row) throw new HTTPException(404, { message: 'Incident not found' });
    const linked = await this.db
      .select()
      .from(alerts)
      .where(eq(alerts.incidentId, id))
      .orderBy(desc(alerts.priorityScore), desc(alerts.lastSeenAt))
      .limit(200);
    const timeline = await this.db
      .select()
      .from(incidentEvents)
      .where(eq(incidentEvents.incidentId, id))
      .orderBy(incidentEvents.occurredAt, incidentEvents.id)
      .limit(500);
    return {
      incident: {
        ...toIncident(row, linked.length),
        allowedNext: allowedNextStates(row.type, row.status),
      },
      alerts: linked.map(toAlert),
      timeline: timeline.map(toTimeline),
    };
  }

  async list(conds: SQL[], limit: number): Promise<Array<IncidentSummary & { _openedAt: Date }>> {
    const alertCount = sql<number>`(select count(*) from ${alerts} where ${alerts.incidentId} = ${incidents.id})`;
    const rows = await this.db
      .select({ incident: incidents, alertCount })
      .from(incidents)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(incidents.openedAt), desc(incidents.id))
      .limit(limit);
    return rows.map((r) => ({
      ...toIncident(r.incident, Number(r.alertCount)),
      _openedAt: r.incident.openedAt,
    }));
  }

  async stats(now = new Date()): Promise<IncidentStats> {
    const byStatus = await this.db
      .select({ k: incidents.status, n: count() })
      .from(incidents)
      .groupBy(incidents.status);
    const bySev = await this.db
      .select({ k: incidents.severity, n: count() })
      .from(incidents)
      .groupBy(incidents.severity);
    const since = new Date(now.getTime() - 30 * 86_400_000);
    const [closed] = await this.db
      .select({
        n: count(),
        mean: sql<
          number | null
        >`avg(extract(epoch from (${incidents.closedAt} - ${incidents.openedAt})))`,
      })
      .from(incidents)
      .where(
        and(
          isNotNull(incidents.closedAt),
          sql`${incidents.closedAt} >= ${since.toISOString()}::timestamptz`,
        ),
      );
    const total = byStatus.reduce((a, r) => a + r.n, 0);
    return {
      total,
      open: total - (byStatus.find((r) => r.k === 'closed')?.n ?? 0),
      byStatus: Object.fromEntries(
        IncidentStatusValues.map((s) => [s, byStatus.find((r) => r.k === s)?.n ?? 0]),
      ) as IncidentStats['byStatus'],
      bySeverity: Object.fromEntries(
        SeverityValues.map((s) => [s, bySev.find((r) => r.k === s)?.n ?? 0]),
      ) as IncidentStats['bySeverity'],
      closedLast30Days: closed?.n ?? 0,
      meanTimeToCloseSeconds:
        closed?.mean === null || closed?.mean === undefined
          ? null
          : Math.max(0, Number(closed.mean)),
      generatedAt: now.toISOString(),
    };
  }
}

export { CLOSED_ALERT_STATUSES };
