import { createHash } from 'node:crypto';
import { eq, inArray, sql } from 'drizzle-orm';
import { HTTPException } from 'hono/http-exception';
import {
  bundleEngineFor,
  bundleManifest,
  parseSuricataRules,
  ruleSeverity,
  ruleTechniques,
  selectBundleRules,
  type ImportRulesRequest,
  type ImportRulesResponse,
  type RuleBundle,
  type RuleDeploymentState,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { detectionRules, sensors, sites } from '../db/schema';
import { sensorSiteCondition } from '../middleware/scope';

export interface RuleActor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export class RuleService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  /** Idempotent import: rules are keyed by (source, gid:sid, rev); identical content is a no-op. */
  async import(input: ImportRulesRequest, actor: RuleActor): Promise<ImportRulesResponse> {
    const parsed = parseSuricataRules(input.content);
    const result: ImportRulesResponse = {
      parsed: parsed.rules.length,
      imported: 0,
      updated: 0,
      unchanged: 0,
      errors: parsed.errors.slice(0, 20),
      errorCount: parsed.errors.length,
    };
    if (parsed.rules.length === 0) return result;
    await this.db.transaction(async (tx) => {
      const keys = parsed.rules.map((r) => `${r.gid}:${r.sid}`);
      const existing = await tx
        .select({
          id: detectionRules.id,
          externalId: detectionRules.externalId,
          revision: detectionRules.revision,
          contentSha256: detectionRules.contentSha256,
        })
        .from(detectionRules)
        .where(
          sql`${detectionRules.source} = ${input.source} and ${detectionRules.externalId} in (${sql.join(
            keys.map((k) => sql`${k}`),
            sql`, `,
          )})`,
        );
      const byKey = new Map(existing.map((e) => [`${e.externalId}@${e.revision}`, e]));
      for (const r of parsed.rules) {
        const externalId = `${r.gid}:${r.sid}`;
        const hash = sha256(r.raw);
        const prev = byKey.get(`${externalId}@${r.rev}`);
        const values = {
          name: r.msg,
          severity: ruleSeverity(r),
          attackTechniques: ruleTechniques(r),
          license: input.license,
          contentSha256: hash,
          enabled: r.enabled,
          action: r.action,
          classtype: r.classtype,
          ruleSet: input.ruleSet,
          content: r.raw.slice(0, 8192),
          importedBy: actor.userId,
        };
        if (prev) {
          if (prev.contentSha256 === hash) {
            result.unchanged++;
            continue;
          }
          // Content changed under the same revision: back to draft, re-validation required.
          await tx
            .update(detectionRules)
            .set({ ...values, lifecycle: 'draft', validatedAt: null })
            .where(eq(detectionRules.id, prev.id));
          result.updated++;
        } else {
          await tx.insert(detectionRules).values({
            source: input.source,
            externalId,
            revision: r.rev,
            lifecycle: 'draft',
            ...values,
          });
          result.imported++;
        }
      }
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'detection_rules.import',
          outcome: 'success',
          targetType: 'rule_set',
          targetId: input.ruleSet,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { source: input.source, license: input.license, ...result, errors: undefined },
        },
        tx,
      );
    });
    return result;
  }

  /** Validation = the stored rule text parses, carries msg/sid, and belongs to a licensed set. */
  async validate(ruleId: string, actor: RuleActor) {
    return this.db.transaction(async (tx) => {
      const [rule] = await tx
        .select()
        .from(detectionRules)
        .where(eq(detectionRules.id, ruleId))
        .limit(1)
        .for('update');
      if (!rule) throw new HTTPException(404, { message: 'Rule not found' });
      if (rule.lifecycle === 'retired')
        throw new HTTPException(409, { message: 'Retired rules cannot be validated' });
      const problems: string[] = [];
      if (!rule.content) problems.push('no stored rule content');
      else {
        const p = parseSuricataRules(rule.content);
        if (p.rules.length !== 1)
          problems.push(p.errors[0]?.message ?? 'rule text does not parse to exactly one rule');
      }
      if (!rule.license) problems.push('rule has no licence');
      const outcome = problems.length ? 'failure' : 'success';
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'detection_rules.validate',
          outcome,
          targetType: 'detection_rule',
          targetId: ruleId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { problems },
        },
        tx,
      );
      if (problems.length)
        throw new HTTPException(422, { message: `Validation failed: ${problems.join('; ')}` });
      const [updated] = await tx
        .update(detectionRules)
        .set({ lifecycle: 'validated', validatedAt: new Date() })
        .where(eq(detectionRules.id, ruleId))
        .returning();
      return updated!;
    });
  }

  /**
   * validated → deployed. Deployment is a separate permission from editing (SoD pair
   * `detection_rules.change` / `detection_rules.deploy`); sensors pick the rule up on their next
   * bundle fetch and acknowledge the digest in their heartbeat.
   */
  async deploy(ruleId: string, actor: RuleActor) {
    return this.db.transaction(async (tx) => {
      const [rule] = await tx
        .select()
        .from(detectionRules)
        .where(eq(detectionRules.id, ruleId))
        .limit(1)
        .for('update');
      if (!rule) throw new HTTPException(404, { message: 'Rule not found' });
      if (rule.lifecycle !== 'validated')
        throw new HTTPException(409, {
          message: `Only validated rules can be deployed (rule is ${rule.lifecycle})`,
        });
      const [updated] = await tx
        .update(detectionRules)
        .set({ lifecycle: 'deployed', deployedAt: new Date() })
        .where(eq(detectionRules.id, ruleId))
        .returning();
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'detection_rules.deploy',
          outcome: 'success',
          targetType: 'detection_rule',
          targetId: ruleId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { externalId: rule.externalId, revision: rule.revision, sites: rule.sites },
        },
        tx,
      );
      return updated!;
    });
  }

  /** Targets must be known site keys; an empty list means every sensor of the engine. */
  async setTargets(ruleId: string, siteKeys: string[], actor: RuleActor) {
    const unique = [...new Set(siteKeys)];
    if (unique.length) {
      const known = await this.db
        .select({ key: sites.key })
        .from(sites)
        .where(inArray(sites.key, unique));
      const missing = unique.filter((k) => !known.some((s) => s.key === k));
      if (missing.length)
        throw new HTTPException(400, { message: `Unknown site(s): ${missing.join(', ')}` });
    }
    return this.db.transaction(async (tx) => {
      const [updated] = await tx
        .update(detectionRules)
        .set({ sites: unique })
        .where(eq(detectionRules.id, ruleId))
        .returning();
      if (!updated) throw new HTTPException(404, { message: 'Rule not found' });
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'detection_rules.targets',
          outcome: 'success',
          targetType: 'detection_rule',
          targetId: ruleId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { sites: unique },
        },
        tx,
      );
      return updated;
    });
  }

  /** Deployed, enabled rules for one sensor (engine + site), with a stable digest. */
  async bundleFor(sensor: {
    id: string;
    kind: string;
    site: string | null;
  }): Promise<RuleBundle | null> {
    const engine = bundleEngineFor(sensor.kind);
    if (!engine) return null;
    const rows = await this.db
      .select()
      .from(detectionRules)
      .where(sql`${detectionRules.lifecycle} = 'deployed' and ${detectionRules.enabled} = true`)
      .limit(20000);
    const selected = selectBundleRules(rows, sensor);
    return {
      engine,
      sensorId: sensor.id,
      site: sensor.site,
      generatedAt: new Date().toISOString(),
      bundleSha256: sha256(bundleManifest(selected)),
      ruleCount: selected.length,
      rules: selected.map((r) => ({
        id: r.id,
        source: r.source,
        externalId: r.externalId,
        revision: r.revision,
        contentSha256: r.contentSha256,
        content: r.content!,
      })),
    };
  }

  /** Expected vs acknowledged bundle per enabled sensor, inside the caller's site scope. */
  async deploymentState(scope: readonly string[] | null): Promise<RuleDeploymentState[]> {
    const rows = await this.db
      .select()
      .from(sensors)
      .where(sql`${sensors.enabled} = true and ${sensorSiteCondition(scope) ?? sql`true`}`)
      .orderBy(sensors.name)
      .limit(500);
    const deployed = await this.db
      .select()
      .from(detectionRules)
      .where(sql`${detectionRules.lifecycle} = 'deployed' and ${detectionRules.enabled} = true`)
      .limit(20000);
    const digests = new Map<string, { sha: string; count: number }>();
    return rows.map((s) => {
      const engine = bundleEngineFor(s.kind);
      let expected: { sha: string; count: number } | null = null;
      if (engine) {
        const key = `${s.kind}|${s.site ?? ''}`;
        expected = digests.get(key) ?? null;
        if (!expected) {
          const sel = selectBundleRules(deployed, { kind: s.kind, site: s.site });
          expected = { sha: sha256(bundleManifest(sel)), count: sel.length };
          digests.set(key, expected);
        }
      }
      return {
        sensorId: s.id,
        sensorName: s.name,
        kind: s.kind,
        site: s.site,
        engine,
        expectedBundleSha256: expected?.sha ?? null,
        expectedRuleCount: expected?.count ?? 0,
        appliedBundleSha256: s.rulesBundleSha256,
        appliedAt: s.rulesBundleAppliedAt?.toISOString() ?? null,
        lastHeartbeatAt: s.lastHeartbeatAt?.toISOString() ?? null,
        inSync:
          expected !== null && s.rulesBundleSha256 !== null && s.rulesBundleSha256 === expected.sha,
      };
    });
  }

  async setLifecycle(ruleId: string, lifecycle: 'disabled' | 'retired', actor: RuleActor) {
    return this.db.transaction(async (tx) => {
      const [updated] = await tx
        .update(detectionRules)
        .set({ lifecycle })
        .where(eq(detectionRules.id, ruleId))
        .returning();
      if (!updated) throw new HTTPException(404, { message: 'Rule not found' });
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'detection_rules.lifecycle',
          outcome: 'success',
          targetType: 'detection_rule',
          targetId: ruleId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { lifecycle },
        },
        tx,
      );
      return updated;
    });
  }
}

/** Resolves engine rule references (`gid:sid:rev`) to registry ids, newest revision first. */
export async function resolveRuleIds(
  db: Db | DbTx,
  refs: readonly string[],
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const externalIds = [
    ...new Set(
      refs.map((r) => r.split(':').slice(0, 2).join(':')).filter((x) => /^\d+:\d+$/.test(x)),
    ),
  ];
  if (externalIds.length === 0) return out;
  const rows = await db
    .select({
      id: detectionRules.id,
      externalId: detectionRules.externalId,
      revision: detectionRules.revision,
    })
    .from(detectionRules)
    .where(inArray(detectionRules.externalId, externalIds));
  for (const ref of refs) {
    const [gid, sid, rev] = ref.split(':');
    const candidates = rows.filter((r) => r.externalId === `${gid}:${sid}`);
    if (candidates.length === 0) continue;
    const exact = candidates.find((r) => String(r.revision) === rev);
    const best = exact ?? candidates.sort((a, b) => b.revision - a.revision)[0]!;
    out.set(ref, best.id);
  }
  return out;
}
