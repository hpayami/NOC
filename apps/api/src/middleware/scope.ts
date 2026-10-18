import { sql, type SQL } from 'drizzle-orm';
import { alerts, assets, networkSegments, securityEvents, sensors } from '../db/schema';
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
