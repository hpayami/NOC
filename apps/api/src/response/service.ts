import { createHash } from 'node:crypto';
import { HTTPException } from 'hono/http-exception';
import { and, desc, eq, gte, inArray, sql, type SQL } from 'drizzle-orm';
import {
  checkApproval,
  requiredApprovals,
  ResponseActionKindValues,
  SeverityValues,
  type Permission,
  type ProposeResponseActionRequest,
  type ResponseActionKind,
  type ResponseActionRecord,
  type ResponseExecutorInfo,
  type Severity,
} from '@noc/shared';
import { canonicalJson, type AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import {
  approvals,
  assets,
  detectionRules,
  incidentEvents,
  incidents,
  responseActions,
  securityEvents,
} from '../db/schema';
import { toEvent } from '../routes/alerts';

export interface Actor {
  userId: string;
  email: string;
  permissions: ReadonlySet<Permission>;
  requestId: string | null;
  ip: string | null;
}

type ActionRow = typeof responseActions.$inferSelect;
type ApprovalRow = typeof approvals.$inferSelect;

interface ExecutionContext {
  tx: DbTx;
  action: ActionRow;
  actor: Actor;
  note: string | undefined;
}
interface Executor {
  description: string;
  execute(ctx: ExecutionContext): Promise<{
    result: Record<string, unknown>;
    verification: 'passed' | 'failed' | 'not_run';
  }>;
  rollback(ctx: ExecutionContext): Promise<Record<string, unknown>>;
}

const sevIndex = (s: Severity) => SeverityValues.indexOf(s);

async function timelineEntry(
  tx: DbTx,
  incidentId: string | null,
  actorId: string,
  note: string,
  payload: Record<string, unknown>,
): Promise<string | null> {
  if (!incidentId) return null;
  const [e] = await tx
    .insert(incidentEvents)
    .values({ incidentId, actorId, kind: 'response_action', note, payload })
    .returning({ id: incidentEvents.id });
  await tx.update(incidents).set({ updatedAt: new Date() }).where(eq(incidents.id, incidentId));
  return e?.id ?? null;
}

/**
 * Executors that exist in this build. Everything that would touch the network, an endpoint,
 * an identity provider or the inline-prevention plane is deliberately absent: those actions
 * can be proposed and approved, but execution is refused until a verified integration exists.
 */
const EXECUTORS: Partial<Record<ResponseActionKind, Executor>> = {
  escalate: {
    description: 'Raises the linked incident to at least high severity and records the request',
    async execute({ tx, action, actor, note }) {
      if (!action.incidentId)
        throw new HTTPException(409, { message: 'escalate requires an incident' });
      const [inc] = await tx
        .select()
        .from(incidents)
        .where(eq(incidents.id, action.incidentId))
        .for('update');
      if (!inc) throw new HTTPException(404, { message: 'Incident not found' });
      const target: Severity = sevIndex(inc.severity) < sevIndex('high') ? 'high' : inc.severity;
      if (target !== inc.severity)
        await tx.update(incidents).set({ severity: target }).where(eq(incidents.id, inc.id));
      const entry = await timelineEntry(
        tx,
        inc.id,
        actor.userId,
        note ?? `Escalation executed: ${action.justification}`,
        {
          actionId: action.id,
          kind: action.kind,
          from: inc.severity,
          to: target,
        },
      );
      return {
        result: { previousSeverity: inc.severity, severity: target, timelineEntryId: entry },
        verification: entry ? 'passed' : 'failed',
      };
    },
    async rollback({ tx, action, actor }) {
      const prev = action.result['previousSeverity'] as Severity | undefined;
      if (action.incidentId && prev && SeverityValues.includes(prev))
        await tx
          .update(incidents)
          .set({ severity: prev })
          .where(eq(incidents.id, action.incidentId));
      await timelineEntry(
        tx,
        action.incidentId,
        actor.userId,
        `Escalation rolled back: ${action.rollbackPlan}`,
        { actionId: action.id, restoredSeverity: prev ?? null },
      );
      return { restoredSeverity: prev ?? null };
    },
  },
  recommend_isolation: {
    description:
      'Records an isolation recommendation on the incident; changes nothing on the network',
    async execute({ tx, action, actor, note }) {
      if (!action.incidentId)
        throw new HTTPException(409, { message: 'recommend_isolation requires an incident' });
      const entry = await timelineEntry(
        tx,
        action.incidentId,
        actor.userId,
        note ??
          `Isolation recommended for ${action.targetType} ${action.targetRef}: ${action.justification}`,
        {
          actionId: action.id,
          kind: action.kind,
          target: { type: action.targetType, ref: action.targetRef },
        },
      );
      return {
        result: { timelineEntryId: entry, advisory: true },
        verification: entry ? 'passed' : 'failed',
      };
    },
    async rollback({ tx, action, actor }) {
      await timelineEntry(
        tx,
        action.incidentId,
        actor.userId,
        `Isolation recommendation withdrawn: ${action.rollbackPlan}`,
        { actionId: action.id },
      );
      return { withdrawn: true };
    },
  },
  collect_evidence: {
    description:
      'Snapshots event ids and hashes for the target (last 7 days, ≤ 200 events) as evidence references',
    async execute({ tx, action, actor }) {
      const since = new Date(Date.now() - 7 * 86_400_000);
      const conds: SQL[] = [gte(securityEvents.eventTime, since)];
      if (action.targetType === 'ip')
        conds.push(
          sql`(${securityEvents.srcIp} = ${action.targetRef}::inet or ${securityEvents.dstIp} = ${action.targetRef}::inet)`,
        );
      else if (action.targetType === 'asset')
        conds.push(
          sql`(${securityEvents.srcAssetId} = ${action.targetRef}::uuid or ${securityEvents.dstAssetId} = ${action.targetRef}::uuid)`,
        );
      else
        throw new HTTPException(409, { message: 'collect_evidence supports ip and asset targets' });
      const rows = await tx
        .select()
        .from(securityEvents)
        .where(and(...conds))
        .orderBy(desc(securityEvents.eventTime))
        .limit(200);
      const evidence = rows.map((r) => ({
        kind: 'event' as const,
        ref: r.id,
        sha256: createHash('sha256')
          .update(canonicalJson(toEvent(r)))
          .digest('hex'),
      }));
      const entry = await timelineEntry(
        tx,
        action.incidentId,
        actor.userId,
        `Evidence collected: ${evidence.length} event reference(s) for ${action.targetType} ${action.targetRef}`,
        {
          actionId: action.id,
          kind: action.kind,
          count: evidence.length,
        },
      );
      return {
        result: {
          count: evidence.length,
          since: since.toISOString(),
          evidence,
          timelineEntryId: entry,
        },
        verification: 'passed',
      };
    },
    async rollback({ tx, action, actor }) {
      // References are not deleted (they are hashes, not data); the rollback is recorded only.
      await timelineEntry(
        tx,
        action.incidentId,
        actor.userId,
        `Evidence collection marked rolled back: ${action.rollbackPlan}`,
        { actionId: action.id },
      );
      return { retainedReferences: (action.result['count'] as number | undefined) ?? 0 };
    },
  },
};

const UNAVAILABLE: Record<Exclude<ResponseActionKind, keyof typeof EXECUTORS>, string> = {
  isolate_endpoint: 'Endpoint isolation needs an EDR/NAC integration; none is configured',
  block_indicator: 'Indicator blocking needs a firewall/DNS-RPZ integration; none is configured',
  disable_session: 'Session disabling needs an identity-provider integration; none is configured',
  update_detection_rule: 'Rule deployment to sensors is a Phase 4 capability',
  enable_inline_prevention:
    'Inline prevention is never enabled by the management plane in this phase',
};

export function executorCatalog(): ResponseExecutorInfo[] {
  return ResponseActionKindValues.map((kind) => {
    const ex = EXECUTORS[kind];
    return {
      kind,
      available: Boolean(ex),
      requiredApprovals: requiredApprovals(kind),
      description: ex ? ex.description : UNAVAILABLE[kind as keyof typeof UNAVAILABLE],
    };
  });
}

export const toRecord = (a: ActionRow, aps: ApprovalRow[]): ResponseActionRecord => ({
  id: a.id,
  kind: a.kind,
  status: a.status,
  incidentId: a.incidentId,
  targetType: a.targetType,
  targetRef: a.targetRef,
  triggeringEvidence: a.triggeringEvidence,
  proposedBy: a.proposedBy,
  executedAt: a.executedAt?.toISOString() ?? null,
  expiresAt: a.expiresAt?.toISOString() ?? null,
  rollbackPlan: a.rollbackPlan,
  rolledBackAt: a.rolledBackAt?.toISOString() ?? null,
  verificationResult: a.verificationResult as ResponseActionRecord['verificationResult'],
  justification: a.justification,
  parameters: a.parameters,
  requiredApprovals: a.requiredApprovals,
  approvals: aps.map((p) => ({
    approverId: p.approverId,
    decision: p.decision,
    justification: p.justification,
    decidedAt: p.decidedAt.toISOString(),
  })),
  approvalsGranted: aps.filter((p) => p.decision === 'approved').length,
  executedBy: a.executedBy,
  result: a.result,
  executorAvailable: Boolean(EXECUTORS[a.kind]),
  createdAt: a.createdAt.toISOString(),
  updatedAt: a.updatedAt.toISOString(),
});

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
const UUID = /^[0-9a-f-]{36}$/;

export class ResponseActionService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  private auditOf(
    actor: Actor,
    action: string,
    targetId: string,
    metadata: Record<string, unknown>,
    outcome: 'success' | 'denied' | 'failure' = 'success',
  ) {
    return {
      actorId: actor.userId,
      actorLabel: actor.email,
      action,
      outcome,
      targetType: 'response_action',
      targetId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata,
    };
  }

  private async approvalsOf(id: string, exec: Db | DbTx = this.db): Promise<ApprovalRow[]> {
    return exec
      .select()
      .from(approvals)
      .where(and(eq(approvals.subjectType, 'response_action'), eq(approvals.subjectId, id)))
      .orderBy(approvals.decidedAt);
  }

  private async lock(tx: DbTx, id: string): Promise<ActionRow> {
    const [row] = await tx
      .select()
      .from(responseActions)
      .where(eq(responseActions.id, id))
      .limit(1)
      .for('update');
    if (!row) throw new HTTPException(404, { message: 'Response action not found' });
    return row;
  }

  /** Lazily marks an action expired; returns the (possibly updated) row. */
  private async expireIfDue(tx: DbTx, row: ActionRow, now: Date): Promise<ActionRow> {
    const live = row.status === 'pending_approval' || row.status === 'approved';
    if (!live || !row.expiresAt || row.expiresAt.getTime() > now.getTime()) return row;
    const [updated] = await tx
      .update(responseActions)
      .set({ status: 'expired', updatedAt: now })
      .where(eq(responseActions.id, row.id))
      .returning();
    return updated!;
  }

  private async validateTarget(input: ProposeResponseActionRequest): Promise<void> {
    switch (input.targetType) {
      case 'ip':
        if (!IPV4.test(input.targetRef) && !IPV6.test(input.targetRef))
          throw new HTTPException(400, { message: 'targetRef must be an IP address' });
        return;
      case 'asset': {
        if (!UUID.test(input.targetRef))
          throw new HTTPException(400, { message: 'targetRef must be an asset id' });
        const [a] = await this.db
          .select({ id: assets.id })
          .from(assets)
          .where(eq(assets.id, input.targetRef))
          .limit(1);
        if (!a) throw new HTTPException(404, { message: 'Target asset not found' });
        return;
      }
      case 'rule': {
        if (!UUID.test(input.targetRef))
          throw new HTTPException(400, { message: 'targetRef must be a detection rule id' });
        const [r] = await this.db
          .select({ id: detectionRules.id })
          .from(detectionRules)
          .where(eq(detectionRules.id, input.targetRef))
          .limit(1);
        if (!r) throw new HTTPException(404, { message: 'Target rule not found' });
        return;
      }
      case 'incident':
        if (!UUID.test(input.targetRef))
          throw new HTTPException(400, { message: 'targetRef must be an incident id' });
        return;
      default:
        return;
    }
  }

  async propose(input: ProposeResponseActionRequest, actor: Actor): Promise<ResponseActionRecord> {
    if (input.kind === 'enable_inline_prevention' && !actor.permissions.has('ips.propose'))
      throw new HTTPException(403, { message: 'enable_inline_prevention requires ips.propose' });
    await this.validateTarget(input);
    if (input.incidentId) {
      const [inc] = await this.db
        .select({ status: incidents.status })
        .from(incidents)
        .where(eq(incidents.id, input.incidentId))
        .limit(1);
      if (!inc) throw new HTTPException(404, { message: 'Incident not found' });
      if (inc.status === 'closed')
        throw new HTTPException(409, { message: 'Cannot propose actions on a closed incident' });
    }
    if ((input.kind === 'escalate' || input.kind === 'recommend_isolation') && !input.incidentId)
      throw new HTTPException(400, { message: `${input.kind} requires an incidentId` });
    const required = requiredApprovals(input.kind);
    const now = new Date();
    const row = await this.db.transaction(async (tx) => {
      const [row] = await tx
        .insert(responseActions)
        .values({
          kind: input.kind,
          status: required === 0 ? 'approved' : 'pending_approval',
          incidentId: input.incidentId,
          targetType: input.targetType,
          targetRef: input.targetRef,
          triggeringEvidence: input.triggeringEvidence,
          proposedBy: actor.userId,
          requiredApprovals: required,
          expiresAt: new Date(now.getTime() + input.expiresInHours * 3_600_000),
          rollbackPlan: input.rollbackPlan,
          justification: input.justification,
          parameters: input.parameters,
          createdAt: now,
          updatedAt: now,
        })
        .returning();
      await timelineEntry(
        tx,
        input.incidentId,
        actor.userId,
        `Response action proposed: ${input.kind} on ${input.targetType} ${input.targetRef}`,
        {
          actionId: row!.id,
          kind: input.kind,
          requiredApprovals: required,
        },
      );
      await this.audit.record(
        this.auditOf(actor, 'response.propose', row!.id, {
          kind: input.kind,
          targetType: input.targetType,
          targetRef: input.targetRef,
          incidentId: input.incidentId,
          requiredApprovals: required,
        }),
        tx,
      );
      return row!;
    });
    return toRecord(row, []);
  }

  async decide(
    id: string,
    decision: 'approved' | 'rejected',
    justification: string,
    actor: Actor,
  ): Promise<ResponseActionRecord> {
    const now = new Date();
    const [peek] = await this.db
      .select()
      .from(responseActions)
      .where(eq(responseActions.id, id))
      .limit(1);
    if (!peek) throw new HTTPException(404, { message: 'Response action not found' });
    const prior = await this.approvalsOf(id);
    const check = checkApproval({
      kind: peek.kind,
      status: peek.status,
      proposedBy: peek.proposedBy,
      approverId: actor.userId,
      approverPermissions: actor.permissions,
      priorApproverIds: prior.map((p) => p.approverId),
      expiresAt: peek.expiresAt,
      now,
    });
    if (!check.ok) {
      // Audited outside the transaction so the denial survives.
      await this.audit.record(
        this.auditOf(
          actor,
          `response.${decision === 'approved' ? 'approve' : 'reject'}`,
          id,
          { code: check.code, status: peek.status },
          check.code === 'forbidden' || check.code === 'self_approval' ? 'denied' : 'failure',
        ),
      );
      if (check.code === 'expired')
        await this.db
          .update(responseActions)
          .set({ status: 'expired', updatedAt: now })
          .where(and(eq(responseActions.id, id), eq(responseActions.status, 'pending_approval')));
      throw new HTTPException(
        check.code === 'forbidden' || check.code === 'self_approval' ? 403 : 409,
        { message: check.message },
      );
    }
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.expireIfDue(tx, await this.lock(tx, id), now);
      if (cur.status !== 'pending_approval')
        throw new HTTPException(409, { message: 'Action is not awaiting approval' });
      await tx.insert(approvals).values({
        subjectType: 'response_action',
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
        .update(responseActions)
        .set({ status, updatedAt: now })
        .where(eq(responseActions.id, id))
        .returning();
      await timelineEntry(
        tx,
        cur.incidentId,
        actor.userId,
        `Response action ${decision}: ${cur.kind} (${granted}/${cur.requiredApprovals} approvals)`,
        { actionId: id, decision, status },
      );
      await this.audit.record(
        this.auditOf(actor, `response.${decision === 'approved' ? 'approve' : 'reject'}`, id, {
          kind: cur.kind,
          granted,
          required: cur.requiredApprovals,
          status,
          justification,
        }),
        tx,
      );
      return updated!;
    });
    return toRecord(row, await this.approvalsOf(id));
  }

  async execute(id: string, note: string | undefined, actor: Actor): Promise<ResponseActionRecord> {
    const now = new Date();
    // Phase 1: claim the action under lock; every refusal here is audited and nothing runs.
    const claimed = await this.db.transaction(async (tx) => {
      const cur = await this.expireIfDue(tx, await this.lock(tx, id), now);
      const aps = await this.approvalsOf(id, tx);
      const refuse = (
        status: number,
        code: string,
        message: string,
        outcome: 'denied' | 'failure' = 'failure',
      ) => {
        return { refusal: { status, code, message, outcome }, cur };
      };
      if (cur.status !== 'approved')
        return refuse(409, 'bad_state', `Action is ${cur.status}, not approved`);
      if (cur.kind === 'enable_inline_prevention' && !actor.permissions.has('ips.enable'))
        return refuse(403, 'forbidden', 'enable_inline_prevention requires ips.enable', 'denied');
      if (aps.some((p) => p.approverId === actor.userId))
        return refuse(403, 'sod', 'An approver may not execute the action they approved', 'denied');
      if (!EXECUTORS[cur.kind])
        return refuse(
          409,
          'executor_unavailable',
          UNAVAILABLE[cur.kind as keyof typeof UNAVAILABLE],
        );
      const [updated] = await tx
        .update(responseActions)
        .set({ status: 'executing', executedBy: actor.userId, updatedAt: now })
        .where(eq(responseActions.id, id))
        .returning();
      return { refusal: null, cur: updated! };
    });
    if (claimed.refusal) {
      await this.audit.record(
        this.auditOf(
          actor,
          'response.execute',
          id,
          { kind: claimed.cur.kind, status: claimed.cur.status, code: claimed.refusal.code },
          claimed.refusal.outcome,
        ),
      );
      throw new HTTPException(claimed.refusal.status as 403 | 409, {
        message: claimed.refusal.message,
      });
    }
    const executor = EXECUTORS[claimed.cur.kind]!;
    // Phase 2: run the executor atomically with the status update; a throw leaves the action `failed`.
    try {
      const row = await this.db.transaction(async (tx) => {
        const out = await executor.execute({ tx, action: claimed.cur, actor, note });
        const status = out.verification === 'failed' ? 'verification_failed' : 'executed';
        const [updated] = await tx
          .update(responseActions)
          .set({
            status,
            executedAt: new Date(),
            verificationResult: out.verification,
            result: { ...out.result, ...(note ? { note } : {}) },
            updatedAt: new Date(),
          })
          .where(eq(responseActions.id, id))
          .returning();
        await this.audit.record(
          this.auditOf(actor, 'response.execute', id, {
            kind: claimed.cur.kind,
            status,
            verification: out.verification,
          }),
          tx,
        );
        return updated!;
      });
      return toRecord(row, await this.approvalsOf(id));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      await this.db
        .update(responseActions)
        .set({ status: 'failed', result: { error: message.slice(0, 512) }, updatedAt: new Date() })
        .where(eq(responseActions.id, id));
      await this.audit.record(
        this.auditOf(
          actor,
          'response.execute',
          id,
          { kind: claimed.cur.kind, error: message.slice(0, 512) },
          'failure',
        ),
      );
      throw err;
    }
  }

  async rollback(
    id: string,
    note: string | undefined,
    actor: Actor,
  ): Promise<ResponseActionRecord> {
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status !== 'executed' && cur.status !== 'verification_failed')
        throw new HTTPException(409, {
          message: `Only executed actions can be rolled back (status: ${cur.status})`,
        });
      const executor = EXECUTORS[cur.kind];
      if (!executor)
        throw new HTTPException(409, {
          message: 'No executor for this kind; nothing was executed by the platform',
        });
      const out = await executor.rollback({ tx, action: cur, actor, note });
      const [updated] = await tx
        .update(responseActions)
        .set({
          status: 'rolled_back',
          rolledBackAt: new Date(),
          result: { ...cur.result, rollback: { ...out, ...(note ? { note } : {}) } },
          updatedAt: new Date(),
        })
        .where(eq(responseActions.id, id))
        .returning();
      await this.audit.record(this.auditOf(actor, 'response.rollback', id, { kind: cur.kind }), tx);
      return updated!;
    });
    return toRecord(row, await this.approvalsOf(id));
  }

  async get(id: string): Promise<ResponseActionRecord> {
    const [row] = await this.db
      .select()
      .from(responseActions)
      .where(eq(responseActions.id, id))
      .limit(1);
    if (!row) throw new HTTPException(404, { message: 'Response action not found' });
    return toRecord(row, await this.approvalsOf(id));
  }

  async list(
    conds: SQL[],
    limit: number,
  ): Promise<Array<ResponseActionRecord & { _createdAt: Date }>> {
    const rows = await this.db
      .select()
      .from(responseActions)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(responseActions.createdAt), desc(responseActions.id))
      .limit(limit);
    if (rows.length === 0) return [];
    const aps = await this.db
      .select()
      .from(approvals)
      .where(
        and(
          eq(approvals.subjectType, 'response_action'),
          inArray(
            approvals.subjectId,
            rows.map((r) => r.id),
          ),
        ),
      )
      .orderBy(approvals.decidedAt);
    return rows.map((r) => ({
      ...toRecord(
        r,
        aps.filter((p) => p.subjectId === r.id),
      ),
      _createdAt: r.createdAt,
    }));
  }
}
