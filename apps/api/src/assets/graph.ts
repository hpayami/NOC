import { HTTPException } from 'hono/http-exception';
import { and, desc, eq, inArray, notInArray, sql } from 'drizzle-orm';
import {
  CLOSED_ALERT_STATUSES,
  RISKY_SERVICES,
  assessAssetRisk,
  exposureTechniques,
  techniqueInfo,
  type AssetGraph,
  type AssetGraphEdge,
  type AssetGraphNode,
  type AssetOpenPort,
  type AssetRiskProfile,
  type AssetTechnique,
  type Severity,
} from '@noc/shared';
import { toFinding } from '../assessments/service';
import type { Db } from '../db/client';
import {
  alerts,
  assetInterfaces,
  assetObservations,
  assetServices,
  assets,
  detectionRules,
  networkSegments,
  securityEvents,
  topologyRelationships,
  vulnerabilityFindings,
} from '../db/schema';
import { assetSiteCondition } from '../middleware/scope';
import { toPublicAsset, toPublicInterface } from '../routes/assets';

type AssetRow = typeof assets.$inferSelect;
const TRAFFIC_EDGE_LIMIT = 5000;
const TOPOLOGY_EDGE_LIMIT = 5000;
const risky = new Map(RISKY_SERVICES.map((r) => [r.port, r]));

function labelOf(a: { hostname: string | null; id: string }, ips: string[]): string {
  return a.hostname ?? ips[0] ?? a.id.slice(0, 8);
}

/**
 * Dependency graph with evidence-only edges. Nodes are the assets inside the caller's site scope
 * (most recently seen first, bounded); edges are recorded topology relationships between two of
 * those nodes plus traffic the sensors saw between them inside the window. Nothing is inferred
 * from addresses or segments; an asset without evidence is an isolated node, not a guess.
 */
export async function assetGraph(
  db: Db,
  sites: readonly string[] | null,
  opts: { hours: number; limit: number; now?: Date },
): Promise<AssetGraph> {
  const now = opts.now ?? new Date();
  const since = new Date(now.getTime() - opts.hours * 3_600_000);
  const scope = assetSiteCondition(sites);
  const rows = await db
    .select({ asset: assets, site: networkSegments.site })
    .from(assets)
    .leftJoin(networkSegments, eq(networkSegments.id, assets.segmentId))
    .where(scope)
    .orderBy(desc(assets.lastSeenAt), desc(assets.id))
    .limit(opts.limit + 1);
  const truncatedNodes = rows.length > opts.limit;
  const kept = rows.slice(0, opts.limit);
  const ids = kept.map((r) => r.asset.id);
  const empty: AssetGraph = {
    nodes: [],
    edges: [],
    window: { from: since.toISOString(), to: now.toISOString() },
    truncated: truncatedNodes,
    generatedAt: now.toISOString(),
  };
  if (ids.length === 0) return empty;

  const [ifaces, findings, openAlerts, services, topo, traffic] = await Promise.all([
    db
      .select({ assetId: assetInterfaces.assetId, ips: assetInterfaces.ipAddresses })
      .from(assetInterfaces)
      .where(inArray(assetInterfaces.assetId, ids)),
    db
      .select({
        assetId: vulnerabilityFindings.assetId,
        severity: vulnerabilityFindings.severity,
        validated: vulnerabilityFindings.validated,
      })
      .from(vulnerabilityFindings)
      .where(
        and(inArray(vulnerabilityFindings.assetId, ids), eq(vulnerabilityFindings.status, 'open')),
      ),
    db
      .select({ assetId: alerts.assetId, severity: alerts.severity })
      .from(alerts)
      .where(
        and(inArray(alerts.assetId, ids), notInArray(alerts.status, [...CLOSED_ALERT_STATUSES])),
      ),
    db
      .selectDistinct({ assetId: assetServices.assetId, port: assetServices.port })
      .from(assetServices)
      .where(inArray(assetServices.assetId, ids)),
    db
      .select()
      .from(topologyRelationships)
      .where(
        and(
          inArray(topologyRelationships.sourceAssetId, ids),
          inArray(topologyRelationships.targetAssetId, ids),
        ),
      )
      .orderBy(desc(topologyRelationships.lastObservedAt))
      .limit(TOPOLOGY_EDGE_LIMIT + 1),
    db
      .select({
        src: securityEvents.srcAssetId,
        dst: securityEvents.dstAssetId,
        n: sql<number>`count(*)::int`,
        last: sql<string>`max(${securityEvents.eventTime})`,
        ports: sql<
          number[]
        >`(array_agg(distinct ${securityEvents.dstPort}) filter (where ${securityEvents.dstPort} is not null))[1:16]`,
      })
      .from(securityEvents)
      .where(
        and(
          sql`${securityEvents.eventTime} >= ${since.toISOString()}::timestamptz`,
          inArray(securityEvents.srcAssetId, ids),
          inArray(securityEvents.dstAssetId, ids),
          sql`${securityEvents.srcAssetId} <> ${securityEvents.dstAssetId}`,
        ),
      )
      .groupBy(securityEvents.srcAssetId, securityEvents.dstAssetId)
      .orderBy(sql`count(*) desc`)
      .limit(TRAFFIC_EDGE_LIMIT + 1),
  ]);

  const ipsOf = new Map<string, string[]>();
  for (const i of ifaces) ipsOf.set(i.assetId, [...(ipsOf.get(i.assetId) ?? []), ...i.ips]);
  const group = <T extends { assetId: string | null }>(xs: T[]) => {
    const m = new Map<string, T[]>();
    for (const x of xs) if (x.assetId) m.set(x.assetId, [...(m.get(x.assetId) ?? []), x]);
    return m;
  };
  const fByAsset = group(findings);
  const aByAsset = group(openAlerts);
  const sByAsset = group(services);

  const nodes: AssetGraphNode[] = kept.map(({ asset: a, site }) => {
    const ips = [...new Set(ipsOf.get(a.id) ?? [])];
    const f = fByAsset.get(a.id) ?? [];
    const al = aByAsset.get(a.id) ?? [];
    const ports = [...new Set((sByAsset.get(a.id) ?? []).map((s) => s.port))];
    return {
      id: a.id,
      label: labelOf(a, ips),
      hostname: a.hostname,
      ipAddresses: ips.slice(0, 8),
      assetClass: a.assetClass,
      segmentId: a.segmentId,
      site: site ?? null,
      criticality: a.criticality,
      operationalStatus: a.operationalStatus,
      monitoringCoverage: a.monitoringCoverage,
      assuranceState: a.assuranceState,
      risk: assessAssetRisk({
        monitoringCoverage: a.monitoringCoverage,
        assuranceState: a.assuranceState,
        openFindings: f.map((x) => ({ severity: x.severity, validated: x.validated })),
        openAlerts: al.map((x) => ({ severity: x.severity })),
        exposures: ports.map((p) => ({ port: p, severity: risky.get(p)?.severity ?? null })),
        criticality: a.criticality,
      }),
      openFindings: f.length,
      openAlerts: al.length,
      openPorts: ports.length,
    };
  });

  const edges: AssetGraphEdge[] = [
    ...topo.slice(0, TOPOLOGY_EDGE_LIMIT).map((e) => ({
      id: `topo:${e.id}`,
      sourceAssetId: e.sourceAssetId,
      targetAssetId: e.targetAssetId,
      kind: e.kind,
      basis: 'topology' as const,
      verification: e.verification,
      evidence: e.evidence,
      weight: 1,
      ports: [],
      lastObservedAt: e.lastObservedAt.toISOString(),
    })),
    ...traffic
      .slice(0, TRAFFIC_EDGE_LIMIT)
      .filter((t): t is typeof t & { src: string; dst: string } => !!t.src && !!t.dst)
      .map((t) => ({
        id: `traffic:${t.src}:${t.dst}`,
        sourceAssetId: t.src,
        targetAssetId: t.dst,
        kind: 'observed_communication' as const,
        basis: 'observed_traffic' as const,
        verification: 'verified' as const,
        evidence: `${t.n} event(s) seen by sensors in the last ${opts.hours} h${t.ports?.length ? `, dst ports ${t.ports.join(', ')}` : ''}`,
        weight: Number(t.n),
        ports: (t.ports ?? []).slice(0, 16),
        lastObservedAt: new Date(t.last).toISOString(),
      })),
  ];
  return {
    ...empty,
    nodes,
    edges,
    truncated:
      truncatedNodes || topo.length > TOPOLOGY_EDGE_LIMIT || traffic.length > TRAFFIC_EDGE_LIMIT,
  };
}

/**
 * Everything the platform knows about one asset's risk, with the source of each statement:
 * open ports (agent inventory, assessment and discovery observations), techniques observed
 * (detections against the asset) versus exposed (what an open service makes available),
 * findings and alerts (each behind its own permission), neighbours with evidence.
 */
export async function assetRiskProfile(
  db: Db,
  id: string,
  principal: { sites: readonly string[] | null; permissions: ReadonlySet<string> },
  opts: { hours?: number; now?: Date } = {},
): Promise<AssetRiskProfile> {
  const now = opts.now ?? new Date();
  const hours = opts.hours ?? 168;
  const since = new Date(now.getTime() - hours * 3_600_000);
  const scope = assetSiteCondition(principal.sites);
  const [row] = await db
    .select({ asset: assets, site: networkSegments.site })
    .from(assets)
    .leftJoin(networkSegments, eq(networkSegments.id, assets.segmentId))
    .where(scope ? and(eq(assets.id, id), scope) : eq(assets.id, id))
    .limit(1);
  if (!row) throw new HTTPException(404, { message: 'Asset not found' });
  const a: AssetRow = row.asset;
  const ifaces = await db.select().from(assetInterfaces).where(eq(assetInterfaces.assetId, id));
  const sensitive = principal.permissions.has('assets.read_sensitive');

  // Open ports: agent inventory first, then assessment/discovery observations (latest wins per port).
  const svc = await db
    .select()
    .from(assetServices)
    .where(eq(assetServices.assetId, id))
    .orderBy(desc(assetServices.lastSeenAt))
    .limit(500);
  const ports = new Map<string, AssetOpenPort>();
  const addPort = (proto: 'tcp' | 'udp', port: number, source: string, at: Date) => {
    const key = `${proto}/${port}`;
    const prev = ports.get(key);
    if (prev && new Date(prev.lastSeenAt) >= at) return;
    const r = risky.get(port);
    ports.set(key, {
      proto,
      port,
      service: r?.service ?? null,
      severity: r?.severity ?? null,
      why: r?.why ?? null,
      source,
      lastSeenAt: at.toISOString(),
    });
  };
  for (const s of svc)
    addPort(s.proto === 'udp' ? 'udp' : 'tcp', s.port, `inventory:${s.source}`, s.lastSeenAt);
  const obs = await db
    .select({
      source: assetObservations.source,
      observedAt: assetObservations.observedAt,
      attributes: assetObservations.attributes,
    })
    .from(assetObservations)
    .where(
      and(eq(assetObservations.assetId, id), sql`${assetObservations.attributes} ? 'openPorts'`),
    )
    .orderBy(desc(assetObservations.observedAt))
    .limit(50);
  for (const o of obs) {
    const raw = (o.attributes as Record<string, unknown>)['openPorts'];
    const list = String(raw ?? '')
      .split(',')
      .map((x) => Number(x.trim()))
      .filter((n) => Number.isInteger(n) && n >= 0 && n <= 65535);
    for (const p of list) addPort('tcp', p, `observation:${o.source}`, o.observedAt);
  }
  const openPorts = [...ports.values()].sort((x, y) => x.port - y.port);

  // Findings (permission-gated), alerts (permission-gated) and techniques.
  const findingsIncluded = principal.permissions.has('findings.read');
  const findingRows = findingsIncluded
    ? await db
        .select()
        .from(vulnerabilityFindings)
        .where(eq(vulnerabilityFindings.assetId, id))
        .orderBy(desc(vulnerabilityFindings.lastDetectedAt))
        .limit(200)
    : [];
  const alertsIncluded = principal.permissions.has('alerts.read');
  const alertRows = alertsIncluded
    ? await db
        .select({ alert: alerts, techniques: detectionRules.attackTechniques })
        .from(alerts)
        .leftJoin(detectionRules, eq(detectionRules.id, alerts.ruleId))
        .where(eq(alerts.assetId, id))
        .orderBy(desc(alerts.lastSeenAt))
        .limit(50)
    : [];
  const techniques = new Map<string, AssetTechnique>();
  const bump = (techniqueId: string, source: 'alert' | 'exposure', evidence: string) => {
    const key = `${source}:${techniqueId}`;
    const cur = techniques.get(key);
    if (cur) {
      cur.count++;
      return;
    }
    const info = techniqueInfo(techniqueId);
    techniques.set(key, {
      techniqueId,
      name: info.name,
      tactic: info.tactic,
      source,
      evidence,
      count: 1,
    });
  };
  for (const r of alertRows)
    for (const t of r.techniques ?? []) bump(t, 'alert', `alert: ${r.alert.title}`);
  for (const p of openPorts)
    for (const t of exposureTechniques(p.port))
      bump(t, 'exposure', `${p.proto}/${p.port} open${p.service ? ` (${p.service})` : ''}`);

  // Neighbours with evidence, both directions.
  const topo = await db
    .select()
    .from(topologyRelationships)
    .where(
      sql`${topologyRelationships.sourceAssetId} = ${id} or ${topologyRelationships.targetAssetId} = ${id}`,
    )
    .limit(100);
  const traffic = await db
    .select({
      src: securityEvents.srcAssetId,
      dst: securityEvents.dstAssetId,
      n: sql<number>`count(*)::int`,
    })
    .from(securityEvents)
    .where(
      and(
        sql`${securityEvents.eventTime} >= ${since.toISOString()}::timestamptz`,
        sql`(${securityEvents.srcAssetId} = ${id} or ${securityEvents.dstAssetId} = ${id})`,
        sql`${securityEvents.srcAssetId} is not null and ${securityEvents.dstAssetId} is not null and ${securityEvents.srcAssetId} <> ${securityEvents.dstAssetId}`,
      ),
    )
    .groupBy(securityEvents.srcAssetId, securityEvents.dstAssetId)
    .limit(100);
  const neighbourIds = new Set<string>();
  for (const e of topo)
    neighbourIds.add(e.sourceAssetId === id ? e.targetAssetId : e.sourceAssetId);
  for (const t of traffic) neighbourIds.add(t.src === id ? t.dst! : t.src!);
  neighbourIds.delete(id);
  const neighbourRows = neighbourIds.size
    ? await db
        .select({ id: assets.id, hostname: assets.hostname })
        .from(assets)
        .where(
          scope
            ? and(inArray(assets.id, [...neighbourIds]), scope)
            : inArray(assets.id, [...neighbourIds]),
        )
    : [];
  const nIps = neighbourIds.size
    ? await db
        .select({ assetId: assetInterfaces.assetId, ips: assetInterfaces.ipAddresses })
        .from(assetInterfaces)
        .where(inArray(assetInterfaces.assetId, [...neighbourIds]))
    : [];
  const visible = new Map(neighbourRows.map((n) => [n.id, n]));
  const labelFor = (nid: string) => {
    const n = visible.get(nid);
    if (!n) return null;
    return labelOf(
      n,
      nIps.filter((x) => x.assetId === nid).flatMap((x) => x.ips),
    );
  };
  const neighbors: AssetRiskProfile['neighbors'] = [];
  for (const e of topo) {
    const other = e.sourceAssetId === id ? e.targetAssetId : e.sourceAssetId;
    const label = labelFor(other);
    if (!label) continue; // outside the caller's scope: not shown, not counted
    neighbors.push({
      assetId: other,
      label,
      kind: e.kind,
      basis: 'topology',
      direction: e.sourceAssetId === id ? 'out' : 'in',
      weight: 1,
    });
  }
  const flows = new Map<string, { in: number; out: number }>();
  for (const t of traffic) {
    const other = t.src === id ? t.dst! : t.src!;
    const f = flows.get(other) ?? { in: 0, out: 0 };
    if (t.src === id) f.out += Number(t.n);
    else f.in += Number(t.n);
    flows.set(other, f);
  }
  for (const [other, f] of flows) {
    const label = labelFor(other);
    if (!label) continue;
    neighbors.push({
      assetId: other,
      label,
      kind: 'observed_communication',
      basis: 'observed_traffic',
      direction: f.in && f.out ? 'both' : f.out ? 'out' : 'in',
      weight: f.in + f.out,
    });
  }

  const openFindings = findingRows.filter((f) => f.status === 'open');
  const openAlerts = alertRows.filter(
    (r) => !(CLOSED_ALERT_STATUSES as readonly string[]).includes(r.alert.status),
  );
  const risk = assessAssetRisk({
    monitoringCoverage: a.monitoringCoverage,
    assuranceState: a.assuranceState,
    openFindings: openFindings.map((f) => ({
      severity: f.severity as Severity,
      validated: f.validated,
    })),
    openAlerts: openAlerts.map((r) => ({ severity: r.alert.severity as Severity })),
    exposures: openPorts.map((p) => ({ port: p.port, severity: p.severity })),
    criticality: a.criticality,
  });
  if (!findingsIncluded)
    risk.basis.push('findings not visible to this account (findings.read missing)');
  if (!alertsIncluded) risk.basis.push('alerts not visible to this account (alerts.read missing)');

  return {
    asset: toPublicAsset(a, ifaces, sensitive),
    site: row.site ?? null,
    risk,
    openPorts,
    techniques: [...techniques.values()].sort(
      (x, y) => y.count - x.count || x.techniqueId.localeCompare(y.techniqueId),
    ),
    alerts: alertRows.map((r) => ({
      id: r.alert.id,
      title: r.alert.title,
      severity: r.alert.severity,
      status: r.alert.status,
      lastSeenAt: r.alert.lastSeenAt.toISOString(),
      occurrenceCount: r.alert.occurrenceCount,
      techniques: r.techniques ?? [],
    })),
    alertsIncluded,
    findings: findingRows.map(toFinding),
    findingsIncluded,
    neighbors: neighbors.sort((x, y) => y.weight - x.weight).slice(0, 100),
    generatedAt: now.toISOString(),
  };
}
// keep the interface mapper import used (public shape parity with GET /assets/{id})
void toPublicInterface;
