import { and, count, eq, gte, lt, max, notInArray, sql, type SQL } from 'drizzle-orm';
import type { PgColumn } from 'drizzle-orm/pg-core';
import {
  IPS_HEARTBEAT_MAX_AGE_SECONDS,
  durationStats,
  renderPostureReportMarkdown,
  type Permission,
  type PostureReport,
  type SectionState,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import {
  alerts,
  assessmentEngagements,
  assessmentRuns,
  assets,
  auditEvents,
  incidents,
  ipsPolicies,
  mlInferenceResults,
  responseActions,
  securityEvents,
  sensors,
  threatIndicatorMatches,
  threatIndicators,
  vulnerabilityFindings,
} from '../db/schema';
import {
  alertSiteCondition,
  assetIdSiteCondition,
  assetSiteCondition,
  eventSiteCondition,
  findingSiteCondition,
  incidentSiteCondition,
  mlResultSiteCondition,
  responseActionSiteCondition,
  sensorSiteCondition,
} from '../middleware/scope';
import type { MlService } from '../ml/service';

export interface Reader {
  userId: string;
  label: string;
  permissions: ReadonlySet<Permission>;
  sites: readonly string[] | null;
  requestId: string | null;
  ip: string | null;
}

/** Score at or above which an advisory result is counted as "high" in the report. */
export const ML_HIGH_SCORE = 0.8;

type Counts = Record<string, number>;
const tally = (rows: Array<{ k: string | null; n: number }>): Counts =>
  Object.fromEntries(rows.map((r) => [r.k ?? 'unknown', Number(r.n)]));
const withhold = (permission: Permission) =>
  ({ state: 'withheld' as SectionState, permission, note: null, data: null }) as const;

/**
 * Period posture report. Every figure comes from a bounded query over records the platform
 * holds, scoped to the reader's sites, and every section states its own state: a section the
 * reader may not see is withheld (never estimated); a plane with nothing recorded says so.
 */
export class ReportService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly ml: Pick<MlService, 'status'>,
  ) {}

  markdown(r: PostureReport): string {
    return renderPostureReportMarkdown(r);
  }

  async posture(reader: Reader, days: number, now = new Date()): Promise<PostureReport> {
    const from = new Date(now.getTime() - days * 86_400_000);
    const sites = reader.sites;
    const can = (p: Permission) => reader.permissions.has(p);
    const inPeriod = (col: PgColumn): SQL => and(gte(col, from), lt(col, now))!;
    const limitations: string[] = [
      `Figures are counts of records the platform holds for ${days} day(s); nothing is sampled or estimated.`,
      'Assets, sensors and events outside the monitored segments are not represented: an absent record is not a safe asset.',
      'Alert acknowledgement time is not tracked per alert, so no mean time to acknowledge is reported.',
      'Engagements, runs and the audit trail are platform-wide and not reduced by site scope.',
    ];
    if (sites !== null)
      limitations.push(
        `Site-scoped to ${sites.length ? sites.join(', ') : 'no site'}: unattributable records are excluded.`,
      );

    const report: PostureReport = {
      generatedAt: now.toISOString(),
      generatedBy: reader.label,
      period: { from: from.toISOString(), to: now.toISOString(), days },
      sites: sites === null ? null : [...sites],
      assets: withhold('assets.read'),
      sensors: withhold('sensors.read'),
      events: withhold('events.read'),
      alerts: withhold('alerts.read'),
      incidents: withhold('incidents.read'),
      response: withhold('response.read'),
      prevention: withhold('ips.read'),
      assessments: withhold('assessments.read'),
      findings: withhold('findings.read'),
      threatIntel: withhold('threat_intel.read'),
      analytics: withhold('ml.read'),
      governance: withhold('audit.read'),
      limitations,
    };

    if (can('assets.read')) {
      const scope = assetSiteCondition(sites);
      const [tot] = await this.db
        .select({
          total: count(),
          seen: sql<number>`count(*) filter (where ${assets.lastSeenAt} >= ${from.toISOString()}::timestamptz)::int`,
        })
        .from(assets)
        .where(scope);
      const cov = await this.db
        .select({ k: assets.monitoringCoverage, n: count() })
        .from(assets)
        .where(scope)
        .groupBy(assets.monitoringCoverage);
      const crit = await this.db
        .select({ k: assets.criticality, n: count() })
        .from(assets)
        .where(scope)
        .groupBy(assets.criticality);
      const total = tot?.total ?? 0;
      report.assets = {
        state: total ? 'available' : 'not_configured',
        permission: 'assets.read',
        note: total ? null : 'no asset recorded in scope',
        data: total
          ? {
              total,
              byCoverage: tally(cov),
              byCriticality: tally(crit),
              seenInPeriod: Number(tot?.seen ?? 0),
            }
          : null,
      };
    }

    if (can('sensors.read')) {
      const scope = sensorSiteCondition(sites);
      const stale = new Date(now.getTime() - IPS_HEARTBEAT_MAX_AGE_SECONDS * 1000).toISOString();
      const [s] = await this.db
        .select({
          total: count(),
          enabled: sql<number>`count(*) filter (where ${sensors.enabled})::int`,
          heartbeating: sql<number>`count(*) filter (where ${sensors.enabled} and ${sensors.lastHeartbeatAt} >= ${stale}::timestamptz)::int`,
          inlineCapable: sql<number>`count(*) filter (where ${sensors.enabled} and ${sensors.inlineCapable})::int`,
        })
        .from(sensors)
        .where(scope);
      const kinds = await this.db
        .select({ k: sensors.kind, n: count() })
        .from(sensors)
        .where(scope)
        .groupBy(sensors.kind);
      const total = s?.total ?? 0;
      const enabled = Number(s?.enabled ?? 0);
      const heartbeating = Number(s?.heartbeating ?? 0);
      report.sensors = {
        state: total ? 'available' : 'not_configured',
        permission: 'sensors.read',
        note: total ? null : 'no sensor registered in scope',
        data: total
          ? {
              total,
              enabled,
              heartbeating,
              silent: enabled - heartbeating,
              byKind: tally(kinds),
              inlineCapable: Number(s?.inlineCapable ?? 0),
            }
          : null,
      };
    }

    if (can('events.read')) {
      const where = and(inPeriod(securityEvents.eventTime), eventSiteCondition(sites));
      const [e] = await this.db
        .select({
          total: count(),
          sensorsReporting: sql<number>`count(distinct ${securityEvents.sourceSensorId})::int`,
        })
        .from(securityEvents)
        .where(where);
      const cat = await this.db
        .select({ k: securityEvents.category, n: count() })
        .from(securityEvents)
        .where(where)
        .groupBy(securityEvents.category);
      const sev = await this.db
        .select({ k: securityEvents.severity, n: count() })
        .from(securityEvents)
        .where(where)
        .groupBy(securityEvents.severity);
      const total = e?.total ?? 0;
      report.events = {
        state: total ? 'available' : 'not_configured',
        permission: 'events.read',
        note: total ? null : 'no event accepted in the period',
        data: total
          ? {
              total,
              byCategory: tally(cat),
              bySeverity: tally(sev),
              sensorsReporting: Number(e?.sensorsReporting ?? 0),
            }
          : null,
      };
    }

    if (can('alerts.read')) {
      const scope = alertSiteCondition(sites);
      const opened = and(inPeriod(alerts.firstSeenAt), scope);
      const [o] = await this.db.select({ n: count() }).from(alerts).where(opened);
      const sev = await this.db
        .select({ k: alerts.severity, n: count() })
        .from(alerts)
        .where(opened)
        .groupBy(alerts.severity);
      const st = await this.db
        .select({ k: alerts.status, n: count() })
        .from(alerts)
        .where(opened)
        .groupBy(alerts.status);
      const [c] = await this.db
        .select({
          closed: sql<number>`count(*) filter (where ${alerts.status} in ('resolved','false_positive') and ${alerts.updatedAt} >= ${from.toISOString()}::timestamptz)::int`,
          fp: sql<number>`count(*) filter (where ${alerts.status} = 'false_positive' and ${alerts.updatedAt} >= ${from.toISOString()}::timestamptz)::int`,
          openNow: sql<number>`count(*) filter (where ${alerts.status} not in ('resolved','false_positive'))::int`,
        })
        .from(alerts)
        .where(scope);
      const n = o?.n ?? 0;
      const any = n > 0 || Number(c?.openNow ?? 0) > 0;
      report.alerts = {
        state: any ? 'available' : 'not_configured',
        permission: 'alerts.read',
        note: any ? null : 'no alert in scope',
        data: any
          ? {
              opened: n,
              bySeverity: tally(sev),
              byStatus: tally(st),
              openAtEnd: Number(c?.openNow ?? 0),
              closedInPeriod: Number(c?.closed ?? 0),
              falsePositives: Number(c?.fp ?? 0),
              meanTimeToAcknowledgeSeconds: null,
            }
          : null,
      };
    }

    if (can('incidents.read')) {
      const scope = incidentSiteCondition(sites);
      const opened = and(inPeriod(incidents.openedAt), scope);
      const [o] = await this.db.select({ n: count() }).from(incidents).where(opened);
      const sev = await this.db
        .select({ k: incidents.severity, n: count() })
        .from(incidents)
        .where(opened)
        .groupBy(incidents.severity);
      const st = await this.db
        .select({ k: incidents.status, n: count() })
        .from(incidents)
        .where(opened)
        .groupBy(incidents.status);
      const closedRows = await this.db
        .select({ openedAt: incidents.openedAt, closedAt: incidents.closedAt })
        .from(incidents)
        .where(and(eq(incidents.status, 'closed'), inPeriod(incidents.closedAt), scope))
        .limit(10_000);
      const [openNow] = await this.db
        .select({ n: count() })
        .from(incidents)
        .where(and(notInArray(incidents.status, ['closed']), scope));
      const d = durationStats(
        closedRows.map((r) => ((r.closedAt?.getTime() ?? 0) - r.openedAt.getTime()) / 1000),
      );
      const n = o?.n ?? 0;
      const any = n > 0 || closedRows.length > 0 || (openNow?.n ?? 0) > 0;
      report.incidents = {
        state: any ? 'available' : 'not_configured',
        permission: 'incidents.read',
        note: any ? null : 'no incident in scope',
        data: any
          ? {
              opened: n,
              closed: closedRows.length,
              openAtEnd: openNow?.n ?? 0,
              bySeverity: tally(sev),
              byStatus: tally(st),
              meanTimeToCloseSeconds: d.mean,
              medianTimeToCloseSeconds: d.median,
            }
          : null,
      };
    }

    if (can('response.read')) {
      const where = and(inPeriod(responseActions.createdAt), responseActionSiteCondition(sites));
      const st = await this.db
        .select({ k: responseActions.status, n: count() })
        .from(responseActions)
        .where(where)
        .groupBy(responseActions.status);
      const by = tally(st);
      const proposed = Object.values(by).reduce((a, b) => a + b, 0);
      report.response = {
        state: proposed ? 'available' : 'not_configured',
        permission: 'response.read',
        note: proposed ? null : 'no response action proposed in the period',
        data: proposed
          ? {
              proposed,
              byStatus: by,
              executed: (by.executed ?? 0) + (by.rolled_back ?? 0),
              rolledBack: by.rolled_back ?? 0,
              rejected: by.rejected ?? 0,
            }
          : null,
      };
    }

    if (can('ips.read')) {
      const scope = sensorSiteCondition(sites);
      const base = this.db
        .select({ k: ipsPolicies.status, n: count() })
        .from(ipsPolicies)
        .innerJoin(sensors, eq(sensors.id, ipsPolicies.sensorId));
      const st = await base.where(scope).groupBy(ipsPolicies.status);
      const [p] = await this.db
        .select({
          enabledInPeriod: sql<number>`count(*) filter (where ${ipsPolicies.enabledAt} >= ${from.toISOString()}::timestamptz)::int`,
          autoDisabled: sql<number>`count(*) filter (where ${ipsPolicies.disableCause} = 'sensor_unhealthy' and ${ipsPolicies.disabledAt} >= ${from.toISOString()}::timestamptz)::int`,
          sensorsInline: sql<number>`count(distinct ${ipsPolicies.sensorId}) filter (where ${ipsPolicies.status} = 'enabled')::int`,
        })
        .from(ipsPolicies)
        .innerJoin(sensors, eq(sensors.id, ipsPolicies.sensorId))
        .where(scope);
      const by = tally(st);
      const total = Object.values(by).reduce((a, b) => a + b, 0);
      report.prevention = {
        state: total ? 'available' : 'not_configured',
        permission: 'ips.read',
        note: total ? null : 'no inline-prevention policy proposed; sensors run detect-only',
        data: total
          ? {
              policiesTotal: total,
              byStatus: by,
              enabledNow: by.enabled ?? 0,
              enabledInPeriod: Number(p?.enabledInPeriod ?? 0),
              autoDisabledInPeriod: Number(p?.autoDisabled ?? 0),
              sensorsInline: Number(p?.sensorsInline ?? 0),
            }
          : null,
      };
    }

    if (can('assessments.read')) {
      const st = await this.db
        .select({ k: assessmentEngagements.status, n: count() })
        .from(assessmentEngagements)
        .groupBy(assessmentEngagements.status);
      const runs = await this.db
        .select({ k: assessmentRuns.status, n: count() })
        .from(assessmentRuns)
        .where(inPeriod(assessmentRuns.createdAt))
        .groupBy(assessmentRuns.status);
      const by = tally(st);
      const total = Object.values(by).reduce((a, b) => a + b, 0);
      const runsBy = tally(runs);
      report.assessments = {
        state: total ? 'available' : 'not_configured',
        permission: 'assessments.read',
        note: total
          ? 'engagements are authorised per scope, not per site'
          : 'no engagement recorded',
        data: total
          ? {
              engagementsTotal: total,
              byStatus: by,
              runsInPeriod: Object.values(runsBy).reduce((a, b) => a + b, 0),
              runsByStatus: runsBy,
            }
          : null,
      };
    }

    if (can('findings.read')) {
      const scope = findingSiteCondition(sites);
      const open = and(eq(vulnerabilityFindings.status, 'open'), scope);
      const [o] = await this.db.select({ n: count() }).from(vulnerabilityFindings).where(open);
      const sev = await this.db
        .select({ k: vulnerabilityFindings.severity, n: count() })
        .from(vulnerabilityFindings)
        .where(open)
        .groupBy(vulnerabilityFindings.severity);
      const [p] = await this.db
        .select({
          newInPeriod: sql<number>`count(*) filter (where ${vulnerabilityFindings.firstDetectedAt} >= ${from.toISOString()}::timestamptz)::int`,
          closedInPeriod: sql<number>`count(*) filter (where ${vulnerabilityFindings.status} in ('mitigated','remediation_verified','false_positive') and ${vulnerabilityFindings.updatedAt} >= ${from.toISOString()}::timestamptz)::int`,
          total: count(),
        })
        .from(vulnerabilityFindings)
        .where(scope);
      const cves = (await this.db.execute(sql`
        select count(distinct c)::int as referenced,
               count(distinct c) filter (where exists (select 1 from vulnerability_catalog v where v.cve_id = c))::int as catalogued,
               count(distinct f.id) filter (where f.status = 'open' and exists (select 1 from vulnerability_catalog v where v.cve_id = c and v.known_exploited))::int as kev_open
        from vulnerability_findings f left join lateral unnest(f.cve) as c on true
        ${scope ? sql`where ${scope}` : sql``}`)) as unknown as Array<{
        referenced: number;
        catalogued: number;
        kev_open: number;
      }>;
      const total = p?.total ?? 0;
      report.findings = {
        state: total ? 'available' : 'not_configured',
        permission: 'findings.read',
        note: total ? null : 'no finding recorded in scope',
        data: total
          ? {
              open: o?.n ?? 0,
              bySeverity: tally(sev),
              newInPeriod: Number(p?.newInPeriod ?? 0),
              closedInPeriod: Number(p?.closedInPeriod ?? 0),
              knownExploitedOpen: Number(cves[0]?.kev_open ?? 0),
              cveReferenced: Number(cves[0]?.referenced ?? 0),
              cveCatalogued: Number(cves[0]?.catalogued ?? 0),
            }
          : null,
      };
    }

    if (can('threat_intel.read')) {
      const [t] = await this.db
        .select({
          active: sql<number>`count(*) filter (where not ${threatIndicators.revoked} and (${threatIndicators.expiresAt} is null or ${threatIndicators.expiresAt} > ${now.toISOString()}::timestamptz))::int`,
          sources: sql<number>`count(distinct ${threatIndicators.source}) filter (where not ${threatIndicators.revoked})::int`,
          lastImportAt: max(threatIndicators.importedAt),
        })
        .from(threatIndicators);
      const mScope = assetIdSiteCondition(sites, sql`${threatIndicatorMatches.assetId}`);
      const m = await this.db
        .select({ k: threatIndicators.type, n: count() })
        .from(threatIndicatorMatches)
        .innerJoin(threatIndicators, eq(threatIndicators.id, threatIndicatorMatches.indicatorId))
        .where(and(inPeriod(threatIndicatorMatches.observedAt), mScope))
        .groupBy(threatIndicators.type);
      const by = tally(m);
      const active = Number(t?.active ?? 0);
      report.threatIntel = {
        state: active ? 'available' : 'not_configured',
        permission: 'threat_intel.read',
        note: active
          ? null
          : 'no active indicator; events are not compared with threat intelligence',
        data: active
          ? {
              activeIndicators: active,
              sources: Number(t?.sources ?? 0),
              matchesInPeriod: Object.values(by).reduce((a, b) => a + b, 0),
              matchesByType: by,
              lastImportAt: t?.lastImportAt?.toISOString() ?? null,
            }
          : null,
      };
    }

    if (can('ml.read')) {
      const where = and(inPeriod(mlInferenceResults.createdAt), mlResultSiteCondition(sites));
      const [r] = await this.db
        .select({
          n: count(),
          high: sql<number>`count(*) filter (where ${mlInferenceResults.score} >= ${ML_HIGH_SCORE})::int`,
        })
        .from(mlInferenceResults)
        .where(where);
      let reachable = false;
      let detail: string | null = null;
      try {
        const st = await this.ml.status();
        reachable = st.reachable;
        detail = st.detail;
      } catch (e) {
        detail = e instanceof Error ? e.message : String(e);
      }
      const n = r?.n ?? 0;
      report.analytics = {
        state: n || reachable ? 'available' : 'unavailable',
        permission: 'ml.read',
        note:
          n || reachable
            ? `advisory only; high = score ≥ ${ML_HIGH_SCORE}`
            : `analysis service unreachable${detail ? `: ${detail}` : ''} and no result stored in the period`,
        data:
          n || reachable
            ? { scoringsInPeriod: n, highScores: Number(r?.high ?? 0), serviceReachable: reachable }
            : null,
      };
    }

    if (can('audit.read')) {
      const where = inPeriod(auditEvents.occurredAt);
      const [a] = await this.db
        .select({
          n: count(),
          denied: sql<number>`count(*) filter (where ${auditEvents.outcome} = 'denied')::int`,
          failures: sql<number>`count(*) filter (where ${auditEvents.outcome} = 'failure')::int`,
          logins: sql<number>`count(*) filter (where ${auditEvents.action} = 'auth.login' and ${auditEvents.outcome} = 'success')::int`,
          loginFailures: sql<number>`count(*) filter (where ${auditEvents.action} = 'auth.login' and ${auditEvents.outcome} = 'denied')::int`,
        })
        .from(auditEvents)
        .where(where);
      let chainVerified: boolean | null = null;
      try {
        chainVerified = (await this.audit.verify()).valid;
      } catch {
        chainVerified = null;
      }
      report.governance = {
        state: 'available',
        permission: 'audit.read',
        note: 'platform-wide; the chain check covers the whole trail',
        data: {
          auditEventsInPeriod: a?.n ?? 0,
          denied: Number(a?.denied ?? 0),
          failures: Number(a?.failures ?? 0),
          chainVerified,
          logins: Number(a?.logins ?? 0),
          loginFailures: Number(a?.loginFailures ?? 0),
        },
      };
    }

    await this.audit.record({
      actorId: reader.userId,
      actorLabel: reader.label,
      action: 'reports.posture',
      outcome: 'success',
      targetType: 'report',
      targetId: null,
      requestId: reader.requestId,
      sourceIp: reader.ip,
      metadata: {
        days,
        sites: sites === null ? 'all' : sites.length,
        withheld: Object.entries(report)
          .filter(
            ([, v]) =>
              v &&
              typeof v === 'object' &&
              'state' in v &&
              (v as { state: string }).state === 'withheld',
          )
          .map(([k]) => k),
      },
    });
    return report;
  }
}
