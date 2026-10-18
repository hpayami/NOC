import { sql, type SQL } from 'drizzle-orm';
import {
  alerts,
  assets,
  incidents,
  mlInferenceResults,
  networkSegments,
  responseActions,
  securityEvents,
  sensors,
  vulnerabilityFindings,
} from '../db/schema';
import type { Db, DbTx } from '../db/client';
import type { Principal } from './context';

/**
 * Site scoping. A principal with `sites === null` is unrestricted; otherwise every list and
 * detail query gets one of these predicates. Rows that cannot be attributed to a site (asset
 * without a segment, alert without an asset, event without an asset) are hidden from restricted
 * principals: fail closed rather than leak.
 */
export const siteScope = (p: Principal | null | undefined): readonly string[] | null =>
  p?.sites ?? null;

const arr = (sites: readonly string[]) =>
  sql`${sql.raw(`ARRAY[${sites.map((s) => `'${s.replace(/'/g, "''")}'`).join(',')}]::text[]`)}`;

export function segmentSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`${networkSegments.site} = any(${arr(sites)})`;
}

export function sensorSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`${sensors.site} = any(${arr(sites)})`;
}

export function assetSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`exists (select 1 from network_segments s where s.id = ${assets.segmentId} and s.site = any(${arr(sites)}))`;
}

export function alertSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`exists (select 1 from assets a join network_segments s on s.id = a.segment_id where a.id = ${alerts.assetId} and s.site = any(${arr(sites)}))`;
}

export function eventSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`exists (select 1 from assets a join network_segments s on s.id = a.segment_id where (a.id = ${securityEvents.srcAssetId} or a.id = ${securityEvents.dstAssetId}) and s.site = any(${arr(sites)}))`;
}

/** Predicate on an arbitrary uuid expression that must name an asset inside the scope. */
export function assetIdSiteCondition(
  sites: readonly string[] | null,
  idExpr: SQL,
): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`exists (select 1 from assets a join network_segments s on s.id = a.segment_id where a.id = ${idExpr} and s.site = any(${arr(sites)}))`;
}

/** Incidents carry their own site; global (null-site) incidents are hidden from restricted users. */
export function incidentSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`${incidents.site} = any(${arr(sites)})`;
}

/** Response actions are visible through their incident; actions without one are hidden. */
export function responseActionSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`exists (select 1 from incidents i where i.id = ${responseActions.incidentId} and i.site = any(${arr(sites)}))`;
}

export function findingSiteCondition(sites: readonly string[] | null): SQL | undefined {
  return assetIdSiteCondition(sites, sql`${vulnerabilityFindings.assetId}`);
}

/** ML results are scoped through their asset subject; non-asset subjects are hidden. */
export function mlResultSiteCondition(sites: readonly string[] | null): SQL | undefined {
  if (sites === null) return undefined;
  if (sites.length === 0) return sql`false`;
  return sql`(${mlInferenceResults.subjectType} = 'asset' and exists (select 1 from assets a join network_segments s on s.id = a.segment_id where a.id::text = ${mlInferenceResults.subjectId} and s.site = any(${arr(sites)})))`;
}

/** Write-side check: may this principal attribute something to `site`? */
export const siteAllowed = (sites: readonly string[] | null, site: string | null): boolean =>
  sites === null || (site !== null && sites.includes(site));

/** Site of an asset through its segment, or null when it cannot be attributed. */
export async function assetSiteOf(exec: Db | DbTx, assetId: string): Promise<string | null> {
  const rows = (await exec.execute(
    sql`select s.site from assets a join network_segments s on s.id = a.segment_id where a.id = ${assetId} limit 1`,
  )) as unknown as Array<{ site: string | null }>;
  return rows[0]?.site ?? null;
}
