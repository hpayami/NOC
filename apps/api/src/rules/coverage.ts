import { and, eq, gte, notInArray, sql } from 'drizzle-orm';
import {
  CLOSED_ALERT_STATUSES,
  computeCoverage,
  engineOfRuleSource,
  exposureTechniques,
  type DetectionCoverage,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { assetServices, assets, detectionRules } from '../db/schema';
import { alertSiteCondition, assetSiteCondition, eventSiteCondition } from '../middleware/scope';
import { RuleService } from './service';

/**
 * Detection coverage per ATT&CK technique: registry rules × sensors that acknowledged the
 * bundle × what the engines observed × what inventoried assets expose. Scoped to the caller's
 * sites through the same predicates every plane uses.
 */
export class DetectionCoverageService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  async coverage(
    scope: readonly string[] | null,
    days: number,
    now = new Date(),
  ): Promise<DetectionCoverage> {
    const since = new Date(now.getTime() - days * 86_400_000);
    const rules = await this.db
      .select({
        lifecycle: detectionRules.lifecycle,
        techniques: detectionRules.attackTechniques,
        source: detectionRules.source,
      })
      .from(detectionRules)
      .where(notInArray(detectionRules.lifecycle, ['retired']))
      .limit(50_000);
    const sensors = (await new RuleService(this.db, this.audit).deploymentState(scope)).map(
      (d) => ({
        engine: d.engine,
        enabled: true,
        inSync: d.inSync,
      }),
    );
    const observedRows = (await this.db.execute(sql`
      select t as technique, count(*)::int as n
      from security_events e, unnest(e.threat_classification) as t
      where e.event_time >= ${since.toISOString()}::timestamptz and t ~ '^T[0-9]{4}(\\.[0-9]{3})?$'
      ${eventSiteCondition(scope) ? sql`and ${eventSiteCondition(scope)}` : sql``}
      group by t`)) as unknown as Array<{ technique: string; n: number }>;
    const alertRows = (await this.db.execute(sql`
      select t as technique, count(distinct a.id)::int as n
      from alerts a join security_events e on e.id = a.last_event_id, unnest(e.threat_classification) as t
      where a.status not in (${sql.join(
        [...CLOSED_ALERT_STATUSES].map((s) => sql`${s}`),
        sql`, `,
      )}) and t ~ '^T[0-9]{4}(\\.[0-9]{3})?$'
      ${alertSiteCondition(scope) ? sql`and ${alertSiteCondition(scope)}` : sql``}
      group by t`)) as unknown as Array<{ technique: string; n: number }>;
    const ports = await this.db
      .selectDistinct({ assetId: assetServices.assetId, port: assetServices.port })
      .from(assetServices)
      .innerJoin(assets, eq(assets.id, assetServices.assetId))
      .where(and(gte(assetServices.lastSeenAt, since), assetSiteCondition(scope)))
      .limit(100_000);
    const exposedAssets = new Map<string, Set<string>>();
    for (const p of ports)
      for (const t of exposureTechniques(p.port)) {
        const set = exposedAssets.get(t) ?? new Set<string>();
        set.add(p.assetId);
        exposedAssets.set(t, set);
      }
    return computeCoverage(
      {
        rules: rules.map((r) => ({
          lifecycle: r.lifecycle,
          techniques: r.techniques,
          engine: engineOfRuleSource(r.source),
        })),
        sensors,
        observed: Object.fromEntries(observedRows.map((r) => [r.technique, Number(r.n)])),
        openAlerts: Object.fromEntries(alertRows.map((r) => [r.technique, Number(r.n)])),
        exposed: Object.fromEntries([...exposedAssets.entries()].map(([t, s]) => [t, s.size])),
        periodDays: days,
      },
      now,
    );
  }
}
