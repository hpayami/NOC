import { HTTPException } from 'hono/http-exception';
import { and, asc, count, desc, eq, inArray, sql, type SQL } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  AssessmentTechniqueValues,
  AuthorizedTargetScope,
  EXECUTABLE_TECHNIQUES,
  evaluateTarget,
  expandTargets,
  findingForOpenPort,
  renderEngagementReportMarkdown,
  reportLimitations,
  targetCoverage,
  techniqueCoverage,
  validateDiscoveryScope,
  validateEngagementTransition,
  type AssessmentRun,
  type AssessmentTechnique,
  type CreateEngagementRequest,
  type CreateRunRequest,
  type EngagementRecord,
  type EngagementReport,
  type EngagementStatus,
  type FindingRecord,
  type Permission,
  type RunDetail,
  type RunSummary,
  type RunTarget,
} from '@noc/shared';
import type { AssetService } from '../assets/service';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { findingSiteCondition } from '../middleware/scope';
import { VulnerabilityService } from '../vulnerabilities/service';
import {
  approvals,
  assessmentEngagements,
  assessmentRunTargets,
  assessmentRuns,
  assessmentScopes,
  networkSegments,
  vulnerabilityFindings,
} from '../db/schema';
import { runTcpCheck } from '../monitoring/service';

export interface Actor {
  userId: string;
  email: string;
  permissions: ReadonlySet<Permission>;
  /** Site grants; null = unrestricted. Findings are scoped through their asset. */
  sites: readonly string[] | null;
  requestId: string | null;
  ip: string | null;
}

type EngRow = typeof assessmentEngagements.$inferSelect;
type ScopeRow = typeof assessmentScopes.$inferSelect;
type RunRow = typeof assessmentRuns.$inferSelect;
type FindingRow = typeof vulnerabilityFindings.$inferSelect;

const TECHNIQUE_NOTES: Record<AssessmentTechnique, string> = {
  passive_discovery:
    'Covered by the always-on passive inventory; nothing to execute per engagement',
  host_discovery:
    'TCP connect to the selected ports; reachable hosts become inventory observations',
  service_fingerprint: 'TCP connect; exposed risky services become observed-exposure findings',
  vulnerability_scan: 'Needs an external scanner integration (none configured)',
  tls_assessment: 'Needs a TLS analysis worker (none configured)',
  config_audit: 'Needs host-agent configuration collection (not implemented)',
  web_scan: 'Needs an external web scanner integration (none configured)',
  dependency_scan: 'Needs an SBOM/dependency source (none configured)',
  detection_validation: 'Needs a traffic-replay worker bound to a sensor (not implemented)',
};

export const techniqueCatalog = () =>
  AssessmentTechniqueValues.map((technique) => ({
    technique,
    executable: EXECUTABLE_TECHNIQUES.includes(technique),
    description: TECHNIQUE_NOTES[technique],
  }));

const scopeOf = (s: ScopeRow): AuthorizedTargetScope =>
  AuthorizedTargetScope.parse({
    includeCidrs: s.includeCidrs,
    includeAddresses: s.includeAddresses,
    excludeCidrs: s.excludeCidrs,
    excludeAddresses: s.excludeAddresses,
    allowPublicAddresses: s.allowPublicAddresses,
    allowedTechniques: s.allowedTechniques,
    windowStart: s.windowStart.toISOString(),
    windowEnd: s.windowEnd.toISOString(),
    maxConcurrency: s.maxConcurrency,
    maxRequestsPerSecond: s.maxRequestsPerSecond,
  });

const toRun = (r: RunRow): AssessmentRun => ({
  id: r.id,
  engagementId: r.engagementId,
  scopeVersion: r.scopeVersion,
  technique: r.technique,
  status: r.status,
  dryRun: r.dryRun,
  ports: r.ports,
  requestedBy: r.requestedBy,
  note: r.note,
  targetCount: r.targetCount,
  startedAt: r.startedAt?.toISOString() ?? null,
  finishedAt: r.finishedAt?.toISOString() ?? null,
  summary: (r.summary as RunSummary | null) ?? null,
  createdAt: r.createdAt.toISOString(),
});

const toTarget = (t: typeof assessmentRunTargets.$inferSelect): RunTarget => ({
  target: t.target,
  decision: t.decision as RunTarget['decision'],
  reasons: t.reasons,
  outcome: t.outcome as RunTarget['outcome'],
  openPorts: t.openPorts,
  observedAt: t.observedAt?.toISOString() ?? null,
});

export const toFinding = (f: FindingRow): FindingRecord => ({
  id: f.id,
  assetId: f.assetId,
  engagementId: f.engagementId,
  title: f.title,
  status: f.status,
  severity: f.severity,
  cve: f.cve,
  cwe: f.cwe,
  cvssBaseScore: f.cvssBaseScore,
  cvssVector: f.cvssVector,
  validated: f.validated,
  evidenceRefs: f.evidenceRefs as FindingRecord['evidenceRefs'],
  firstDetectedAt: f.firstDetectedAt.toISOString(),
  lastDetectedAt: f.lastDetectedAt.toISOString(),
  description: f.description,
  lastNote: f.lastNote,
  updatedAt: f.updatedAt.toISOString(),
  vulnerabilities: [],
});

class RateGate {
  private next = 0;
  constructor(private readonly rps: number) {}
  async wait(): Promise<void> {
    const now = Date.now();
    const slot = Math.max(now, this.next);
    this.next = slot + 1000 / this.rps;
    if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
  }
}

/**
 * Assessment engagements: authorisation first, versioned scope, independent approval, window
 * enforcement, and workers that re-check the scope for every target before any packet leaves.
 * In-platform workers are connect-level only and additionally obey segment discovery policy.
 */
export class AssessmentService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly assets: AssetService,
    private readonly logger: Logger,
  ) {}

  private auditOf(
    actor: Actor | null,
    action: string,
    targetType: string,
    targetId: string,
    metadata: Record<string, unknown>,
    outcome: 'success' | 'denied' | 'failure' = 'success',
  ) {
    return {
      actorId: actor?.userId ?? null,
      actorLabel: actor?.email ?? 'system:assessments',
      action,
      outcome,
      targetType,
      targetId,
      requestId: actor?.requestId ?? null,
      sourceIp: actor?.ip ?? null,
      metadata,
    };
  }

  private async currentScope(exec: Db | DbTx, eng: EngRow): Promise<ScopeRow> {
    const [s] = await exec
      .select()
      .from(assessmentScopes)
      .where(
        and(
          eq(assessmentScopes.engagementId, eng.id),
          eq(assessmentScopes.version, eng.scopeVersion),
        ),
      )
      .limit(1);
    if (!s) throw new HTTPException(500, { message: 'Engagement scope missing' });
    return s;
  }

  private async record(exec: Db | DbTx, eng: EngRow): Promise<EngagementRecord> {
    const scope = await this.currentScope(exec, eng);
    const aps = await exec
      .select()
      .from(approvals)
      .where(
        and(eq(approvals.subjectType, 'assessment_engagement'), eq(approvals.subjectId, eng.id)),
      )
      .orderBy(approvals.decidedAt);
    const [runs] = await exec
      .select({ n: count() })
      .from(assessmentRuns)
      .where(eq(assessmentRuns.engagementId, eng.id));
    const [findings] = await exec
      .select({ n: count() })
      .from(vulnerabilityFindings)
      .where(eq(vulnerabilityFindings.engagementId, eng.id));
    return {
      id: eng.id,
      reference: eng.reference,
      authorizingOrganization: eng.authorizingOrganization,
      authorizationReference: eng.authorizationReference,
      objective: eng.objective,
      status: eng.status,
      responsibleOperatorId: eng.responsibleOperatorId,
      scope: scopeOf(scope),
      scopeVersion: eng.scopeVersion,
      approvedScopeVersion: eng.approvedScopeVersion,
      approvals: aps.map((a) => ({
        approverId: a.approverId,
        decision: a.decision,
        justification: a.justification,
        decidedAt: a.decidedAt.toISOString(),
        scopeVersion: a.subjectVersion ?? 1,
      })),
      dataHandlingRestrictions: eng.dataHandlingRestrictions,
      stopConditions: eng.stopConditions,
      emergencyContact: eng.emergencyContact,
      evidenceRetentionDays: eng.evidenceRetentionDays,
      activatedAt: eng.activatedAt?.toISOString() ?? null,
      completedAt: eng.completedAt?.toISOString() ?? null,
      closeReason: eng.closeReason,
      runCount: runs?.n ?? 0,
      findingCount: findings?.n ?? 0,
      createdAt: eng.createdAt.toISOString(),
      updatedAt: eng.updatedAt.toISOString(),
    };
  }

  private async lock(tx: DbTx, id: string): Promise<EngRow> {
    const [row] = await tx
      .select()
      .from(assessmentEngagements)
      .where(eq(assessmentEngagements.id, id))
      .limit(1)
      .for('update');
    if (!row) throw new HTTPException(404, { message: 'Engagement not found' });
    return row;
  }

  private validateScope(scope: AuthorizedTargetScope): void {
    if (Date.parse(scope.windowEnd) <= Date.parse(scope.windowStart))
      throw new HTTPException(400, { message: 'windowEnd must be after windowStart' });
    if (Date.parse(scope.windowEnd) <= Date.now())
      throw new HTTPException(400, { message: 'Authorisation window already ended' });
    if (scope.includeCidrs.length + scope.includeAddresses.length === 0)
      throw new HTTPException(400, { message: 'Scope has no targets' });
  }

  async create(input: CreateEngagementRequest, actor: Actor): Promise<EngagementRecord> {
    this.validateScope(input.scope);
    const row = await this.db.transaction(async (tx) => {
      const [eng] = await tx
        .insert(assessmentEngagements)
        .values({
          reference: input.reference,
          authorizingOrganization: input.authorizingOrganization,
          responsibleOperatorId: actor.userId,
          authorizationReference: input.authorizationReference,
          status: 'draft',
          dataHandlingRestrictions: input.dataHandlingRestrictions,
          stopConditions: input.stopConditions,
          emergencyContact: input.emergencyContact,
          evidenceRetentionDays: input.evidenceRetentionDays,
          objective: input.objective,
          createdBy: actor.userId,
          scopeVersion: 1,
        })
        .returning();
      await this.insertScope(tx, eng!.id, 1, input.scope);
      await this.audit.record(
        this.auditOf(actor, 'assessments.create', 'engagement', eng!.id, {
          reference: input.reference,
          authorizationReference: input.authorizationReference,
          includeCidrs: input.scope.includeCidrs,
          includeAddresses: input.scope.includeAddresses,
          techniques: input.scope.allowedTechniques,
        }),
        tx,
      );
      return eng!;
    });
    return this.record(this.db, row);
  }

  private insertScope(
    tx: DbTx,
    engagementId: string,
    version: number,
    scope: AuthorizedTargetScope,
  ) {
    return tx.insert(assessmentScopes).values({
      engagementId,
      version,
      includeCidrs: scope.includeCidrs,
      includeAddresses: scope.includeAddresses,
      excludeCidrs: scope.excludeCidrs,
      excludeAddresses: scope.excludeAddresses,
      allowPublicAddresses: scope.allowPublicAddresses,
      allowedTechniques: scope.allowedTechniques,
      windowStart: new Date(scope.windowStart),
      windowEnd: new Date(scope.windowEnd),
      maxConcurrency: scope.maxConcurrency,
      maxRequestsPerSecond: scope.maxRequestsPerSecond,
    });
  }

  /** New scope version. An approved/active engagement drops back to pending approval. */
  async updateScope(
    id: string,
    scope: AuthorizedTargetScope,
    reason: string,
    actor: Actor,
  ): Promise<EngagementRecord> {
    this.validateScope(scope);
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (['completed', 'cancelled', 'expired'].includes(cur.status))
        throw new HTTPException(409, { message: `Engagement is ${cur.status}` });
      const version = cur.scopeVersion + 1;
      await this.insertScope(tx, id, version, scope);
      const reapproval = ['approved', 'active', 'paused'].includes(cur.status);
      const [updated] = await tx
        .update(assessmentEngagements)
        .set({
          scopeVersion: version,
          status: reapproval ? 'pending_approval' : cur.status,
          updatedAt: new Date(),
        })
        .where(eq(assessmentEngagements.id, id))
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'assessments.scope_change', 'engagement', id, {
          version,
          reason,
          reapprovalRequired: reapproval,
          from: cur.status,
        }),
        tx,
      );
      return updated!;
    });
    return this.record(this.db, row);
  }

  private permissionFor(to: EngagementStatus): Permission[] {
    switch (to) {
      case 'pending_approval':
        return ['assessments.plan'];
      case 'active':
      case 'paused':
      case 'completed':
        return ['assessments.execute'];
      case 'cancelled':
        return ['assessments.plan', 'assessments.approve'];
      default:
        return [];
    }
  }

  async transition(
    id: string,
    to: EngagementStatus,
    reason: string | undefined,
    actor: Actor,
  ): Promise<EngagementRecord> {
    const allowed = this.permissionFor(to);
    if (!allowed.some((p) => actor.permissions.has(p))) {
      await this.audit.record(
        this.auditOf(
          actor,
          'assessments.transition',
          'engagement',
          id,
          { to, missing: allowed },
          'denied',
        ),
      );
      throw new HTTPException(403, {
        message: `Transition to ${to} requires ${allowed.join(' or ')}`,
      });
    }
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      const t = validateEngagementTransition(cur.status, to, reason);
      if (!t.ok) throw new HTTPException(409, { message: t.message });
      const now = new Date();
      if (to === 'active') {
        if (cur.approvedScopeVersion !== cur.scopeVersion)
          throw new HTTPException(409, { message: 'Current scope version is not approved' });
        const scope = scopeOf(await this.currentScope(tx, cur));
        if (now.getTime() < Date.parse(scope.windowStart))
          throw new HTTPException(409, { message: 'Authorisation window has not started' });
        if (now.getTime() >= Date.parse(scope.windowEnd))
          throw new HTTPException(409, { message: 'Authorisation window has ended' });
      }
      const [updated] = await tx
        .update(assessmentEngagements)
        .set({
          status: to,
          activatedAt: to === 'active' && !cur.activatedAt ? now : cur.activatedAt,
          completedAt: to === 'completed' || to === 'cancelled' ? now : cur.completedAt,
          closeReason:
            to === 'completed' || to === 'cancelled' ? (reason ?? null) : cur.closeReason,
          updatedAt: now,
        })
        .where(eq(assessmentEngagements.id, id))
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'assessments.transition', 'engagement', id, {
          from: cur.status,
          to,
          reason: reason ?? null,
        }),
        tx,
      );
      return updated!;
    });
    return this.record(this.db, row);
  }

  /** Independent approval: never the responsible operator or the creator. One approval suffices. */
  async decide(
    id: string,
    decision: 'approved' | 'rejected',
    justification: string,
    actor: Actor,
  ): Promise<EngagementRecord> {
    const now = new Date();
    const [peek] = await this.db
      .select()
      .from(assessmentEngagements)
      .where(eq(assessmentEngagements.id, id))
      .limit(1);
    if (!peek) throw new HTTPException(404, { message: 'Engagement not found' });
    const action = decision === 'approved' ? 'assessments.approve' : 'assessments.reject';
    if (actor.userId === peek.responsibleOperatorId || actor.userId === peek.createdBy) {
      await this.audit.record(
        this.auditOf(actor, action, 'engagement', id, { code: 'self_approval' }, 'denied'),
      );
      throw new HTTPException(403, {
        message: 'The responsible operator cannot approve their own engagement',
      });
    }
    const row = await this.db.transaction(async (tx) => {
      const cur = await this.lock(tx, id);
      if (cur.status !== 'pending_approval')
        throw new HTTPException(409, {
          message: `Engagement is ${cur.status}, not awaiting approval`,
        });
      await tx.insert(approvals).values({
        subjectType: 'assessment_engagement',
        subjectId: id,
        subjectVersion: cur.scopeVersion,
        approverId: actor.userId,
        decision,
        justification,
        decidedAt: now,
      });
      if (decision === 'approved')
        await tx
          .update(assessmentScopes)
          .set({ approvedBy: actor.userId, approvedAt: now })
          .where(
            and(
              eq(assessmentScopes.engagementId, id),
              eq(assessmentScopes.version, cur.scopeVersion),
            ),
          );
      const [updated] = await tx
        .update(assessmentEngagements)
        .set({
          status: decision === 'approved' ? 'approved' : 'draft',
          approvedScopeVersion:
            decision === 'approved' ? cur.scopeVersion : cur.approvedScopeVersion,
          updatedAt: now,
        })
        .where(eq(assessmentEngagements.id, id))
        .returning();
      await this.audit.record(
        this.auditOf(actor, action, 'engagement', id, {
          scopeVersion: cur.scopeVersion,
          justification,
        }),
        tx,
      );
      return updated!;
    });
    return this.record(this.db, row);
  }

  /** Authorisation windows end on their own: approved/active/paused engagements past windowEnd expire. */
  async expireDue(now = new Date()): Promise<number> {
    const due = await this.db
      .select({ id: assessmentEngagements.id })
      .from(assessmentEngagements)
      .innerJoin(
        assessmentScopes,
        and(
          eq(assessmentScopes.engagementId, assessmentEngagements.id),
          eq(assessmentScopes.version, assessmentEngagements.scopeVersion),
        ),
      )
      .where(
        and(
          inArray(assessmentEngagements.status, ['approved', 'active', 'paused']),
          sql`${assessmentScopes.windowEnd} <= ${now.toISOString()}::timestamptz`,
        ),
      );
    for (const d of due) {
      await this.db
        .update(assessmentEngagements)
        .set({
          status: 'expired',
          completedAt: now,
          closeReason: 'Authorisation window ended',
          updatedAt: now,
        })
        .where(eq(assessmentEngagements.id, d.id));
      await this.db
        .update(assessmentRuns)
        .set({ status: 'cancelled', finishedAt: now, updatedAt: now })
        .where(
          and(eq(assessmentRuns.engagementId, d.id), inArray(assessmentRuns.status, ['queued'])),
        );
      await this.audit.record(this.auditOf(null, 'assessments.expire', 'engagement', d.id, {}));
    }
    return due.length;
  }

  async get(id: string): Promise<EngagementRecord> {
    await this.expireDue();
    const [row] = await this.db
      .select()
      .from(assessmentEngagements)
      .where(eq(assessmentEngagements.id, id))
      .limit(1);
    if (!row) throw new HTTPException(404, { message: 'Engagement not found' });
    return this.record(this.db, row);
  }

  async list(conds: SQL[], limit: number): Promise<EngagementRecord[]> {
    await this.expireDue();
    const rows = await this.db
      .select()
      .from(assessmentEngagements)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(assessmentEngagements.createdAt))
      .limit(limit);
    const out: EngagementRecord[] = [];
    for (const r of rows) out.push(await this.record(this.db, r));
    return out;
  }

  private segmentPolicies() {
    return this.db
      .select({
        id: networkSegments.id,
        cidr: networkSegments.cidr,
        activeDiscoveryAllowed: networkSegments.activeDiscoveryAllowed,
      })
      .from(networkSegments);
  }

  /** The in-platform worker posture: connect-level techniques, private targets inside discovery-allowed segments. */
  private async workerPolicy(scope: AuthorizedTargetScope, technique: AssessmentTechnique) {
    const restricted: AuthorizedTargetScope = { ...scope, allowedTechniques: [technique] };
    return validateDiscoveryScope(restricted, await this.segmentPolicies());
  }

  async createRun(
    engagementId: string,
    input: CreateRunRequest,
    actor: Actor,
  ): Promise<AssessmentRun> {
    await this.expireDue();
    const row = await this.db.transaction(async (tx) => {
      const eng = await this.lock(tx, engagementId);
      if (eng.status !== 'active')
        throw new HTTPException(409, {
          message: `Engagement is ${eng.status}; runs need an active engagement`,
        });
      if (eng.approvedScopeVersion !== eng.scopeVersion)
        throw new HTTPException(409, { message: 'Current scope version is not approved' });
      const scope = scopeOf(await this.currentScope(tx, eng));
      if (!scope.allowedTechniques.includes(input.technique))
        throw new HTTPException(409, {
          message: `Technique ${input.technique} is not in the authorised scope`,
        });
      if (!EXECUTABLE_TECHNIQUES.includes(input.technique))
        throw new HTTPException(409, {
          message: `No worker for ${input.technique}: ${TECHNIQUE_NOTES[input.technique]}`,
        });
      const policy = await this.workerPolicy(scope, input.technique);
      if (!policy.ok)
        throw new HTTPException(422, {
          message: `Worker policy refused the scope: ${policy.reasons.join('; ')}`,
        });
      const targets = expandTargets(scope);
      const [run] = await tx
        .insert(assessmentRuns)
        .values({
          engagementId,
          scopeVersion: eng.scopeVersion,
          technique: input.technique,
          dryRun: input.dryRun,
          ports: input.ports,
          requestedBy: actor.userId,
          note: input.note ?? null,
          targetCount: targets.length,
        })
        .returning();
      if (targets.length)
        await tx
          .insert(assessmentRunTargets)
          .values(targets.map((target) => ({ runId: run!.id, target })));
      await this.audit.record(
        this.auditOf(actor, 'assessments.run_create', 'assessment_run', run!.id, {
          engagementId,
          technique: input.technique,
          dryRun: input.dryRun,
          targetCount: targets.length,
          ports: input.ports,
        }),
        tx,
      );
      return run!;
    });
    return toRun(row);
  }

  async cancelRun(runId: string, actor: Actor): Promise<AssessmentRun> {
    const row = await this.db.transaction(async (tx) => {
      const [run] = await tx
        .select()
        .from(assessmentRuns)
        .where(eq(assessmentRuns.id, runId))
        .limit(1)
        .for('update');
      if (!run) throw new HTTPException(404, { message: 'Run not found' });
      if (run.status !== 'queued' && run.status !== 'running')
        throw new HTTPException(409, { message: `Run is ${run.status}` });
      const [updated] = await tx
        .update(assessmentRuns)
        .set({
          status: 'cancelled',
          finishedAt: run.status === 'queued' ? new Date() : run.finishedAt,
          updatedAt: new Date(),
        })
        .where(eq(assessmentRuns.id, runId))
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'assessments.run_cancel', 'assessment_run', runId, {
          from: run.status,
        }),
        tx,
      );
      return updated!;
    });
    return toRun(row);
  }

  /** Claims a queued run and executes it; scope and policy are re-evaluated inside the worker. */
  async executeRun(runId: string, actor: Actor): Promise<AssessmentRun> {
    const claimed = await this.db.transaction(async (tx) => {
      const [run] = await tx
        .select()
        .from(assessmentRuns)
        .where(eq(assessmentRuns.id, runId))
        .limit(1)
        .for('update');
      if (!run) throw new HTTPException(404, { message: 'Run not found' });
      if (run.status !== 'queued')
        throw new HTTPException(409, { message: `Run is ${run.status}; only queued runs execute` });
      const eng = await this.lock(tx, run.engagementId);
      if (eng.status !== 'active')
        throw new HTTPException(409, { message: `Engagement is ${eng.status}` });
      if (eng.scopeVersion !== run.scopeVersion || eng.approvedScopeVersion !== run.scopeVersion)
        throw new HTTPException(409, {
          message: 'Scope changed since the run was created; create a new run',
        });
      const [updated] = await tx
        .update(assessmentRuns)
        .set({ status: 'running', startedAt: new Date(), updatedAt: new Date() })
        .where(eq(assessmentRuns.id, runId))
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'assessments.run_start', 'assessment_run', runId, {
          technique: run.technique,
          dryRun: run.dryRun,
        }),
        tx,
      );
      return { run: updated!, scope: scopeOf(await this.currentScope(tx, eng)) };
    });
    return this.work(claimed.run, claimed.scope, actor);
  }

  private async work(
    run: RunRow,
    scope: AuthorizedTargetScope,
    actor: Actor,
  ): Promise<AssessmentRun> {
    const summary: RunSummary = {
      allowed: 0,
      denied: 0,
      reachable: 0,
      unreachable: 0,
      skipped: 0,
      findingsCreated: 0,
      findingsUpdated: 0,
    };
    const finish = async (status: 'completed' | 'cancelled' | 'failed') => {
      const [updated] = await this.db
        .update(assessmentRuns)
        .set({ status, finishedAt: new Date(), summary, updatedAt: new Date() })
        .where(eq(assessmentRuns.id, run.id))
        .returning();
      await this.audit.record(
        this.auditOf(
          actor,
          'assessments.run_finish',
          'assessment_run',
          run.id,
          { status, ...summary },
          status === 'failed' ? 'failure' : 'success',
        ),
      );
      return toRun(updated!);
    };
    const policy = await this.workerPolicy(scope, run.technique);
    if (!policy.ok) {
      this.logger.warn(
        { runId: run.id, reasons: policy.reasons },
        'assessment scope no longer valid at run time',
      );
      return finish('failed');
    }
    const targets = await this.db
      .select()
      .from(assessmentRunTargets)
      .where(eq(assessmentRunTargets.runId, run.id))
      .orderBy(asc(assessmentRunTargets.target));
    const gate = new RateGate(scope.maxRequestsPerSecond);
    const queue = [...targets];
    let cancelled = false;
    let processed = 0;
    const isCancelled = async () => {
      const [r] = await this.db
        .select({ status: assessmentRuns.status })
        .from(assessmentRuns)
        .where(eq(assessmentRuns.id, run.id))
        .limit(1);
      return r?.status === 'cancelled';
    };
    const mark = (id: string, patch: Partial<typeof assessmentRunTargets.$inferInsert>) =>
      this.db.update(assessmentRunTargets).set(patch).where(eq(assessmentRunTargets.id, id));

    const worker = async () => {
      for (let t = queue.shift(); t; t = queue.shift()) {
        if (cancelled || (processed++ % 16 === 0 && (await isCancelled()))) {
          cancelled = true;
          await mark(t.id, { outcome: 'skipped' });
          summary.skipped++;
          continue;
        }
        const now = new Date();
        const decision = evaluateTarget({ scope, target: t.target, technique: run.technique, now });
        if (!decision.allowed) {
          summary.denied++;
          await mark(t.id, {
            decision: 'denied',
            reasons: decision.reasons,
            outcome: 'skipped',
            observedAt: now,
          });
          continue;
        }
        summary.allowed++;
        if (run.dryRun) {
          summary.skipped++;
          await mark(t.id, { decision: 'allowed', outcome: 'skipped', observedAt: now });
          continue;
        }
        const open: number[] = [];
        for (const port of run.ports) {
          await gate.wait();
          const r = await runTcpCheck(t.target, port, 1500);
          if (r.outcome === 'up') open.push(port);
        }
        const reachable = open.length > 0;
        if (reachable) {
          summary.reachable++;
          // An IP is never an identity, so an IP-only observation would mint a new asset on every
          // run. Reuse the asset that already owns the address when exactly one does; otherwise
          // record the observation and let identity resolution decide.
          // Address-only observation: identity resolution re-attaches it to the single asset
          // holding the address (or reports ambiguity, in which case no finding is recorded).
          const res = await this.assets.ingest(
            {
              source: `assessment:${run.engagementId}`,
              method: 'tcp_service_check',
              observedAt: now.toISOString(),
              identifiers: { macAddresses: [], ipAddresses: [t.target], hostnames: [] },
              attributes: { openPorts: open.join(','), assessmentRunId: run.id },
            },
            {
              userId: actor.userId,
              label: actor.email,
              requestId: actor.requestId,
              ip: actor.ip,
            },
          );
          const assetId = res.assetId;
          if (run.technique === 'service_fingerprint' && assetId)
            await this.recordFindings(run, assetId, t.target, open, now, summary);
        } else summary.unreachable++;
        await mark(t.id, {
          decision: 'allowed',
          outcome: reachable ? 'reachable' : 'unreachable',
          openPorts: open,
          observedAt: now,
        });
      }
    };
    try {
      await Promise.all(
        Array.from({ length: Math.min(scope.maxConcurrency, Math.max(1, targets.length)) }, worker),
      );
    } catch (err) {
      this.logger.error({ err, runId: run.id }, 'assessment run failed');
      return finish('failed');
    }
    return finish(cancelled ? 'cancelled' : 'completed');
  }

  /** The single asset owning this address, or null when none or several do. */
  /** Observed exposures become findings; a repeat observation updates lastDetectedAt and evidence, never the triage status. */
  private async recordFindings(
    run: RunRow,
    assetId: string,
    target: string,
    open: number[],
    now: Date,
    summary: RunSummary,
  ) {
    for (const port of open) {
      const f = findingForOpenPort(port);
      if (!f) continue;
      const evidence = { kind: 'note' as const, ref: `assessment_run:${run.id}:${target}:${port}` };
      const [existing] = await this.db
        .select()
        .from(vulnerabilityFindings)
        .where(
          and(eq(vulnerabilityFindings.assetId, assetId), eq(vulnerabilityFindings.title, f.title)),
        )
        .limit(1);
      if (existing) {
        const refs = [
          ...(existing.evidenceRefs as Array<{ kind: string; ref: string }>),
          evidence,
        ].slice(-32);
        await this.db
          .update(vulnerabilityFindings)
          .set({
            lastDetectedAt: now,
            evidenceRefs: refs,
            engagementId: existing.engagementId ?? run.engagementId,
            updatedAt: now,
          })
          .where(eq(vulnerabilityFindings.id, existing.id));
        summary.findingsUpdated++;
      } else {
        await this.db.insert(vulnerabilityFindings).values({
          assetId,
          engagementId: run.engagementId,
          title: f.title,
          severity: f.severity,
          cwe: f.cwe,
          validated: true,
          evidenceRefs: [evidence],
          description: f.description,
          firstDetectedAt: now,
          lastDetectedAt: now,
          updatedAt: now,
        });
        summary.findingsCreated++;
      }
    }
  }

  async listRuns(engagementId: string): Promise<AssessmentRun[]> {
    const rows = await this.db
      .select()
      .from(assessmentRuns)
      .where(eq(assessmentRuns.engagementId, engagementId))
      .orderBy(desc(assessmentRuns.createdAt))
      .limit(200);
    return rows.map(toRun);
  }

  async runDetail(runId: string): Promise<RunDetail> {
    const [run] = await this.db
      .select()
      .from(assessmentRuns)
      .where(eq(assessmentRuns.id, runId))
      .limit(1);
    if (!run) throw new HTTPException(404, { message: 'Run not found' });
    const targets = await this.db
      .select()
      .from(assessmentRunTargets)
      .where(eq(assessmentRunTargets.runId, runId))
      .orderBy(asc(assessmentRunTargets.target))
      .limit(5000);
    const findings = await this.db
      .select()
      .from(vulnerabilityFindings)
      .where(
        and(
          eq(vulnerabilityFindings.engagementId, run.engagementId),
          sql`${vulnerabilityFindings.evidenceRefs}::text like ${`%assessment_run:${runId}:%`}`,
        ),
      )
      .orderBy(desc(vulnerabilityFindings.severity))
      .limit(500);
    return {
      run: toRun(run),
      targets: targets.map(toTarget),
      findings: await new VulnerabilityService(this.db, this.audit).attach(
        findings.map((f) => toFinding(f)),
      ),
    };
  }

  /**
   * Engagement report: scope, approvals, runs, per-address coverage and findings, with the
   * limitations computed from the same records. Findings are included only for holders of
   * findings.read and only inside the actor's site scope; the export is audited.
   */
  async report(engagementId: string, actor: Actor): Promise<EngagementReport> {
    const engagement = await this.get(engagementId);
    const runs = await this.listRuns(engagementId);
    const runTargetRows =
      runs.length === 0
        ? []
        : await this.db
            .select()
            .from(assessmentRunTargets)
            .where(
              inArray(
                assessmentRunTargets.runId,
                runs.map((r) => r.id),
              ),
            )
            .limit(50_000);
    const findingsIncluded = actor.permissions.has('findings.read');
    const findings = findingsIncluded
      ? await this.listFindings(
          [
            eq(vulnerabilityFindings.engagementId, engagementId),
            ...(findingSiteCondition(actor.sites) ? [findingSiteCondition(actor.sites)!] : []),
          ],
          2000,
        )
      : [];
    const scopeTargets = expandTargets(engagement.scope);
    const techniques = techniqueCoverage(engagement.scope.allowedTechniques, runs);
    const { targets, summary } = targetCoverage({
      scopeTargets,
      runs,
      runTargets: runTargetRows.map((t) => ({ ...toTarget(t), runId: t.runId })),
      findings,
    });
    const report: EngagementReport = {
      generatedAt: new Date().toISOString(),
      generatedBy: actor.userId,
      engagement,
      techniques,
      runs,
      coverage: summary,
      targets,
      findings,
      findingsIncluded,
      limitations: reportLimitations({
        engagement,
        techniques,
        runs,
        coverage: summary,
        findingsIncluded,
        findings,
      }),
    };
    await this.audit.record(
      this.auditOf(actor, 'assessments.report', 'assessment_engagement', engagementId, {
        runs: runs.length,
        findings: findings.length,
        findingsIncluded,
        targets: targets.length,
      }),
    );
    return report;
  }

  reportMarkdown(report: EngagementReport): string {
    return renderEngagementReportMarkdown(report);
  }

  async listFindings(conds: SQL[], limit: number): Promise<FindingRecord[]> {
    const rows = await this.db
      .select()
      .from(vulnerabilityFindings)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(vulnerabilityFindings.lastDetectedAt))
      .limit(limit);
    return new VulnerabilityService(this.db, this.audit).attach(rows.map(toFinding));
  }

  async updateFinding(
    id: string,
    status: FindingRecord['status'],
    note: string,
    actor: Actor,
  ): Promise<FindingRecord> {
    const row = await this.db.transaction(async (tx) => {
      const [cur] = await tx
        .select()
        .from(vulnerabilityFindings)
        .where(and(eq(vulnerabilityFindings.id, id), findingSiteCondition(actor.sites)))
        .limit(1)
        .for('update');
      if (!cur) throw new HTTPException(404, { message: 'Finding not found' });
      const [updated] = await tx
        .update(vulnerabilityFindings)
        .set({ status, lastNote: note, updatedAt: new Date() })
        .where(eq(vulnerabilityFindings.id, id))
        .returning();
      await this.audit.record(
        this.auditOf(actor, 'findings.update', 'finding', id, {
          from: cur.status,
          to: status,
          note,
        }),
        tx,
      );
      return updated!;
    });
    return toFinding(row);
  }
}
