import { asc, eq, sql } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  AuthorizedTargetScope,
  DiscoveryJob,
  DiscoveryJobSummary,
  DiscoveryJobTarget,
  evaluateTarget,
  expandTargets,
  validateDiscoveryScope,
  type CreateDiscoveryJobRequest,
  type AuthorizedTargetScope as Scope,
} from '@noc/shared';
import { HTTPException } from 'hono/http-exception';
import type { AssetService } from '../assets/service';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { discoveryJobTargets, discoveryJobs, networkSegments } from '../db/schema';
import { runTcpCheck } from '../monitoring/service';

export interface Actor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

type JobRow = typeof discoveryJobs.$inferSelect;

export const toJob = (j: JobRow) =>
  DiscoveryJob.parse({
    id: j.id,
    name: j.name,
    status: j.status,
    dryRun: j.dryRun,
    scope: AuthorizedTargetScope.parse(j.scope),
    ports: j.ports,
    requestedBy: j.requestedBy,
    approvedBy: j.approvedBy,
    approvalNote: j.approvalNote,
    targetCount: j.targetCount,
    startedAt: j.startedAt?.toISOString() ?? null,
    finishedAt: j.finishedAt?.toISOString() ?? null,
    summary: j.summary ? DiscoveryJobSummary.parse(j.summary) : null,
    createdAt: j.createdAt.toISOString(),
  });

export const toTarget = (t: typeof discoveryJobTargets.$inferSelect) =>
  DiscoveryJobTarget.parse({
    target: t.target,
    decision: t.decision,
    reasons: t.reasons,
    outcome: t.outcome,
    openPorts: t.openPorts,
    observedAt: t.observedAt?.toISOString() ?? null,
  });

/** Token-bucket pacing for outbound probes: never more than `rps` connection attempts per second. */
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

export class DiscoveryService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly assets: AssetService,
    private readonly logger: Logger,
  ) {}

  private async segmentPolicies() {
    return this.db
      .select({
        id: networkSegments.id,
        cidr: networkSegments.cidr,
        activeDiscoveryAllowed: networkSegments.activeDiscoveryAllowed,
      })
      .from(networkSegments);
  }

  async create(input: CreateDiscoveryJobRequest, actor: Actor) {
    const policy = validateDiscoveryScope(input.scope, await this.segmentPolicies());
    if (!policy.ok)
      throw new HTTPException(422, { message: `Scope rejected: ${policy.reasons.join('; ')}` });
    if (Date.parse(input.scope.windowEnd) <= Date.now())
      throw new HTTPException(422, {
        message: 'Scope rejected: authorization window already ended',
      });
    const targets = expandTargets(input.scope);
    return this.db.transaction(async (tx) => {
      const [job] = await tx
        .insert(discoveryJobs)
        .values({
          name: input.name,
          dryRun: input.dryRun,
          scope: input.scope,
          ports: input.ports,
          requestedBy: actor.userId,
          targetCount: targets.length,
        })
        .returning();
      if (targets.length)
        await tx
          .insert(discoveryJobTargets)
          .values(targets.map((target) => ({ jobId: job!.id, target })));
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'discovery.job_request',
          outcome: 'success',
          targetType: 'discovery_job',
          targetId: job!.id,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: {
            name: input.name,
            dryRun: input.dryRun,
            targetCount: targets.length,
            includeCidrs: input.scope.includeCidrs,
            includeAddresses: input.scope.includeAddresses,
          },
        },
        tx,
      );
      return job!;
    });
  }

  /** Two-person rule: the approver can never be the requester (enforced here, not only by roles). */
  async decide(jobId: string, decision: 'approved' | 'rejected', note: string, actor: Actor) {
    const [existing] = await this.db
      .select({ requestedBy: discoveryJobs.requestedBy, status: discoveryJobs.status })
      .from(discoveryJobs)
      .where(eq(discoveryJobs.id, jobId))
      .limit(1);
    if (!existing) throw new HTTPException(404, { message: 'Job not found' });
    if (existing.requestedBy === actor.userId) {
      // Recorded outside the transaction below so the denial persists even though we throw.
      await this.audit.record({
        actorId: actor.userId,
        actorLabel: actor.label,
        action: 'discovery.job_decision',
        outcome: 'denied',
        targetType: 'discovery_job',
        targetId: jobId,
        requestId: actor.requestId,
        sourceIp: actor.ip,
        metadata: { reason: 'self_approval' },
      });
      throw new HTTPException(403, { message: 'Requester cannot approve their own job' });
    }
    return this.db.transaction(async (tx) => {
      const [job] = await tx
        .select()
        .from(discoveryJobs)
        .where(eq(discoveryJobs.id, jobId))
        .limit(1)
        .for('update');
      if (!job) throw new HTTPException(404, { message: 'Job not found' });
      if (job.status !== 'pending_approval')
        throw new HTTPException(409, { message: `Job is ${job.status}` });
      const [updated] = await tx
        .update(discoveryJobs)
        .set({
          status: decision,
          approvedBy: actor.userId,
          approvalNote: note,
          updatedAt: new Date(),
        })
        .where(eq(discoveryJobs.id, jobId))
        .returning();
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'discovery.job_decision',
          outcome: 'success',
          targetType: 'discovery_job',
          targetId: jobId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { decision, note },
        },
        tx,
      );
      return updated!;
    });
  }

  async cancel(jobId: string, actor: Actor) {
    return this.db.transaction(async (tx) => {
      const [job] = await tx
        .select()
        .from(discoveryJobs)
        .where(eq(discoveryJobs.id, jobId))
        .limit(1)
        .for('update');
      if (!job) throw new HTTPException(404, { message: 'Job not found' });
      if (!['pending_approval', 'approved', 'running'].includes(job.status))
        throw new HTTPException(409, { message: `Job is ${job.status}` });
      const [updated] = await tx
        .update(discoveryJobs)
        .set({
          status: 'cancelled',
          finishedAt: job.status === 'running' ? null : new Date(),
          updatedAt: new Date(),
        })
        .where(eq(discoveryJobs.id, jobId))
        .returning();
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'discovery.job_cancel',
          outcome: 'success',
          targetType: 'discovery_job',
          targetId: jobId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
        },
        tx,
      );
      return updated!;
    });
  }

  /** Claims an approved job for execution. Separate from `runJob` so the route can return 202. */
  async claim(jobId: string, actor: Actor): Promise<JobRow> {
    return this.db.transaction(async (tx) => {
      const [job] = await tx
        .select()
        .from(discoveryJobs)
        .where(eq(discoveryJobs.id, jobId))
        .limit(1)
        .for('update');
      if (!job) throw new HTTPException(404, { message: 'Job not found' });
      if (job.status !== 'approved')
        throw new HTTPException(409, { message: `Job is ${job.status}; only approved jobs run` });
      const [updated] = await tx
        .update(discoveryJobs)
        .set({ status: 'running', startedAt: new Date(), updatedAt: new Date() })
        .where(eq(discoveryJobs.id, jobId))
        .returning();
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'discovery.job_run',
          outcome: 'success',
          targetType: 'discovery_job',
          targetId: jobId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { dryRun: job.dryRun },
        },
        tx,
      );
      return updated!;
    });
  }

  /**
   * Executes a claimed (running) job. The scope policy and the per-target check are re-evaluated
   * here, inside the worker, immediately before any connection attempt; cancellation is honoured
   * between targets; pacing and concurrency follow the approved budgets.
   */
  async runJob(jobId: string, actor: Actor): Promise<DiscoveryJobSummary> {
    const [job] = await this.db
      .select()
      .from(discoveryJobs)
      .where(eq(discoveryJobs.id, jobId))
      .limit(1);
    if (!job || job.status !== 'running')
      throw new HTTPException(409, { message: 'Job is not running' });
    const scope: Scope = AuthorizedTargetScope.parse(job.scope);
    const summary: DiscoveryJobSummary = {
      allowed: 0,
      denied: 0,
      reachable: 0,
      unreachable: 0,
      skipped: 0,
      observationsCreated: 0,
    };
    const finish = async (status: 'completed' | 'cancelled' | 'failed') => {
      await this.db
        .update(discoveryJobs)
        .set({ status, finishedAt: new Date(), summary, updatedAt: new Date() })
        .where(eq(discoveryJobs.id, jobId));
      await this.audit.record({
        actorId: actor.userId,
        actorLabel: actor.label,
        action: 'discovery.job_finish',
        outcome: status === 'failed' ? 'failure' : 'success',
        targetType: 'discovery_job',
        targetId: jobId,
        requestId: actor.requestId,
        sourceIp: actor.ip,
        metadata: { status, ...summary },
      });
      return summary;
    };

    const policy = validateDiscoveryScope(scope, await this.segmentPolicies());
    if (!policy.ok) {
      this.logger.warn(
        { jobId, reasons: policy.reasons },
        'discovery scope no longer valid at run time',
      );
      return finish('failed');
    }
    const technique = scope.allowedTechniques.includes('service_fingerprint')
      ? 'service_fingerprint'
      : 'host_discovery';
    const targets = await this.db
      .select()
      .from(discoveryJobTargets)
      .where(eq(discoveryJobTargets.jobId, jobId))
      .orderBy(asc(discoveryJobTargets.target));
    const gate = new RateGate(scope.maxRequestsPerSecond);
    const queue = [...targets];
    let cancelled = false;
    let processed = 0;

    const isCancelled = async () => {
      const [j] = await this.db
        .select({ status: discoveryJobs.status })
        .from(discoveryJobs)
        .where(eq(discoveryJobs.id, jobId))
        .limit(1);
      return j?.status === 'cancelled';
    };

    const worker = async () => {
      for (let t = queue.shift(); t; t = queue.shift()) {
        if (cancelled || (processed++ % 16 === 0 && (await isCancelled()))) {
          cancelled = true;
          await this.db
            .update(discoveryJobTargets)
            .set({ outcome: 'skipped' })
            .where(eq(discoveryJobTargets.id, t.id));
          summary.skipped++;
          continue;
        }
        const now = new Date();
        const decision = evaluateTarget({ scope, target: t.target, technique, now });
        if (!decision.allowed) {
          summary.denied++;
          await this.db
            .update(discoveryJobTargets)
            .set({
              decision: 'denied',
              reasons: decision.reasons,
              outcome: 'skipped',
              observedAt: now,
            })
            .where(eq(discoveryJobTargets.id, t.id));
          continue;
        }
        summary.allowed++;
        if (job.dryRun) {
          summary.skipped++;
          await this.db
            .update(discoveryJobTargets)
            .set({ decision: 'allowed', outcome: 'skipped', observedAt: now })
            .where(eq(discoveryJobTargets.id, t.id));
          continue;
        }
        const open: number[] = [];
        for (const port of job.ports) {
          await gate.wait();
          const r = await runTcpCheck(t.target, port, 1500);
          if (r.outcome === 'up') open.push(port);
        }
        const reachable = open.length > 0;
        if (reachable) {
          summary.reachable++;
          const res = await this.assets.ingest(
            {
              source: `discovery:${jobId}`,
              method: 'tcp_service_check',
              observedAt: now.toISOString(),
              identifiers: { macAddresses: [], ipAddresses: [t.target], hostnames: [] },
              attributes: { openPorts: open.join(','), discoveryJobId: jobId },
            },
            { userId: actor.userId, label: actor.label, requestId: actor.requestId, ip: actor.ip },
          );
          if (res.decision.action !== 'ambiguous') summary.observationsCreated++;
        } else summary.unreachable++;
        await this.db
          .update(discoveryJobTargets)
          .set({
            decision: 'allowed',
            outcome: reachable ? 'reachable' : 'unreachable',
            openPorts: open,
            observedAt: now,
          })
          .where(eq(discoveryJobTargets.id, t.id));
      }
    };
    try {
      await Promise.all(
        Array.from({ length: Math.min(scope.maxConcurrency, Math.max(1, targets.length)) }, worker),
      );
    } catch (err) {
      this.logger.error({ err, jobId }, 'discovery job failed');
      return finish('failed');
    }
    return finish(cancelled ? 'cancelled' : 'completed');
  }
}

export { sql };
