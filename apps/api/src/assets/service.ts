import { and, desc, eq, inArray, isNotNull, or, sql, type SQL } from 'drizzle-orm';
import {
  CREATE_CONFIDENCE,
  isIpOnlyObservation,
  resolveAssetIdentity,
  type CandidateAsset,
  type DiscoveryMethod,
  type IngestObservationRequest,
  type ResolutionDecision,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { assetInterfaces, assetObservations, assets } from '../db/schema';

export interface IngestActor {
  userId: string | null;
  label: string;
  requestId: string | null;
  ip: string | null;
}

export interface IngestResult {
  observationId: string;
  assetId: string | null;
  decision: ResolutionDecision;
}

/** Inventory attributes a collector may report; copied onto the asset only where the asset has no value yet. */
const FILLABLE_ATTRIBUTES = [
  'osName',
  'osVersion',
  'firmwareVersion',
  'manufacturer',
  'model',
  'cpuArchitecture',
  'serialNumber',
  'role',
] as const;

const unique = <T>(xs: T[]) => [...new Set(xs)];
const macArray = (macs: string[]): SQL =>
  sql`ARRAY[${sql.join(
    macs.map((m) => sql`${m}::macaddr`),
    sql`, `,
  )}]`;
const textArray = (xs: string[]): SQL =>
  sql`ARRAY[${sql.join(
    xs.map((x) => sql`${x}::text`),
    sql`, `,
  )}]`;

export class AssetService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  /**
   * Persists one observation and links it to an asset through deterministic identity resolution.
   * Resolution runs under a transaction-scoped advisory lock so concurrent observations of a new
   * device cannot create duplicate assets.
   */
  async ingest(input: IngestObservationRequest, actor: IngestActor): Promise<IngestResult> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext('noc_asset_resolution'))`);
      const ids = input.identifiers;
      const macs = unique(ids.macAddresses.map((m) => m.toLowerCase()));
      const hostnames = unique(ids.hostnames.map((h) => h.trim()));
      const segmentId = await inferSegment(tx, ids.ipAddresses);

      const candidates = await loadCandidates(tx, {
        macs,
        hostnames,
        agentId: ids.agentId,
        cloudInstanceId: ids.cloudInstanceId,
        // Address-only observations may re-attach to the current holder of the address only.
        ipsIfAddressOnly: isIpOnlyObservation({
          macAddresses: macs,
          ipAddresses: ids.ipAddresses,
          hostnames,
          agentId: ids.agentId ?? null,
          cloudInstanceId: ids.cloudInstanceId ?? null,
        })
          ? [...ids.ipAddresses]
          : [],
      });
      const decision = resolveAssetIdentity(
        {
          macAddresses: macs,
          ipAddresses: ids.ipAddresses,
          hostnames,
          agentId: ids.agentId ?? null,
          cloudInstanceId: ids.cloudInstanceId ?? null,
          segmentId,
        },
        candidates,
      );

      const observedAt = new Date(input.observedAt);
      const provenance = {
        source: input.source,
        method: input.method,
        observedAt: input.observedAt,
        confidence: decision.action === 'match' ? decision.confidence : CREATE_CONFIDENCE,
      };
      let assetId: string | null = null;

      if (decision.action === 'create') {
        const fill = fillableFrom(input.attributes);
        const [created] = await tx
          .insert(assets)
          .values({
            hostname: hostnames[0] ?? null,
            segmentId,
            discoveryMethods: [input.method],
            firstSeenAt: observedAt,
            lastSeenAt: observedAt,
            operationalStatus: 'unknown',
            // No sensor covers anything yet; an API-reported asset is known to be unmonitored.
            monitoringCoverage: 'unmonitored',
            assuranceState: 'asset_not_monitored',
            dataConfidence: CREATE_CONFIDENCE,
            provenance: [provenance],
            ...fill,
          })
          .returning({ id: assets.id });
        assetId = created!.id;
      } else if (decision.action === 'match') {
        assetId = decision.assetId;
        const [current] = await tx.select().from(assets).where(eq(assets.id, assetId)).limit(1);
        if (!current) throw new Error('matched asset vanished during resolution');
        const fill = fillableFrom(input.attributes, current);
        const prov = [
          ...(Array.isArray(current.provenance) ? current.provenance : []),
          provenance,
        ].slice(-32);
        await tx
          .update(assets)
          .set({
            ...fill,
            hostname: current.hostname ?? hostnames[0] ?? null,
            segmentId: current.segmentId ?? segmentId,
            lastSeenAt: observedAt > current.lastSeenAt ? observedAt : current.lastSeenAt,
            firstSeenAt: observedAt < current.firstSeenAt ? observedAt : current.firstSeenAt,
            discoveryMethods: unique([
              ...current.discoveryMethods,
              input.method,
            ]) as DiscoveryMethod[],
            dataConfidence: Math.max(current.dataConfidence, decision.confidence),
            provenance: prov,
            updatedAt: new Date(),
          })
          .where(eq(assets.id, assetId));
      }

      if (assetId) await upsertInterfaces(tx, assetId, macs, ids.ipAddresses);

      const [obs] = await tx
        .insert(assetObservations)
        .values({
          assetId,
          source: input.source,
          method: input.method,
          observedAt,
          macAddresses: macs,
          ipAddresses: ids.ipAddresses,
          hostnames,
          cloudInstanceId: ids.cloudInstanceId ?? null,
          agentId: ids.agentId ?? null,
          attributes: input.attributes,
          conflictsWith: decision.action === 'ambiguous' ? decision.candidateIds : [],
        })
        .returning({ id: assetObservations.id });

      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action:
            decision.action === 'ambiguous'
              ? 'assets.observation_ambiguous'
              : 'assets.observation_ingested',
          outcome: 'success',
          targetType: 'asset',
          targetId: assetId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: {
            observationId: obs!.id,
            source: input.source,
            method: input.method,
            decision,
          },
        },
        tx,
      );
      return { observationId: obs!.id, assetId, decision };
    });
  }
}

/** Most specific configured segment whose CIDR contains one of the observed addresses. */
async function inferSegment(tx: DbTx, ips: readonly string[]): Promise<string | null> {
  for (const ip of ips) {
    const rows = (await tx.execute(
      sql`select id from network_segments where cidr is not null and ${ip}::inet <<= cidr order by masklen(cidr) desc limit 1`,
    )) as unknown as Array<{ id: string }>;
    if (rows[0]) return rows[0].id;
  }
  return null;
}

/** Candidate assets: any asset whose linked observations share a stable identifier with the new one. */
async function loadCandidates(
  tx: DbTx,
  k: {
    macs: string[];
    hostnames: string[];
    agentId?: string | undefined;
    cloudInstanceId?: string | undefined;
    /** Set only for address-only observations: candidates are the current owners of the addresses. */
    ipsIfAddressOnly?: string[];
  },
): Promise<CandidateAsset[]> {
  const conds: SQL[] = [];
  if (k.macs.length) conds.push(sql`${assetObservations.macAddresses} && ${macArray(k.macs)}`);
  if (k.hostnames.length)
    conds.push(sql`${assetObservations.hostnames} && ${textArray(k.hostnames)}`);
  if (k.agentId) conds.push(eq(assetObservations.agentId, k.agentId));
  if (k.cloudInstanceId) conds.push(eq(assetObservations.cloudInstanceId, k.cloudInstanceId));
  let candidateIds: string[] = [];
  if (conds.length > 0) {
    const hits = await tx
      .selectDistinct({ assetId: assetObservations.assetId })
      .from(assetObservations)
      .where(and(isNotNull(assetObservations.assetId), or(...conds)))
      .limit(50);
    candidateIds = hits.map((h) => h.assetId).filter((x): x is string => !!x);
  } else if (k.ipsIfAddressOnly?.length) {
    const owners = await tx
      .selectDistinct({ assetId: assetInterfaces.assetId })
      .from(assetInterfaces)
      .where(
        sql`${assetInterfaces.ipAddresses} && ARRAY[${sql.join(
          k.ipsIfAddressOnly.map((ip) => sql`${ip}::inet`),
          sql`, `,
        )}]`,
      )
      .limit(50);
    candidateIds = owners.map((o) => o.assetId);
  }
  if (candidateIds.length === 0) return [];

  const [assetRows, obsRows] = await Promise.all([
    tx
      .select({ id: assets.id, segmentId: assets.segmentId, hostname: assets.hostname })
      .from(assets)
      .where(inArray(assets.id, candidateIds)),
    tx
      .select()
      .from(assetObservations)
      .where(inArray(assetObservations.assetId, candidateIds))
      .orderBy(desc(assetObservations.observedAt))
      .limit(1000),
  ]);
  return assetRows.map((a) => {
    const mine = obsRows.filter((o) => o.assetId === a.id);
    return {
      id: a.id,
      segmentId: a.segmentId,
      macAddresses: unique(mine.flatMap((o) => o.macAddresses)),
      ipAddresses: unique(mine.flatMap((o) => o.ipAddresses)),
      hostnames: unique([...(a.hostname ? [a.hostname] : []), ...mine.flatMap((o) => o.hostnames)]),
      agentId: mine.find((o) => o.agentId)?.agentId ?? null,
      cloudInstanceId: mine.find((o) => o.cloudInstanceId)?.cloudInstanceId ?? null,
    };
  });
}

/**
 * Keeps one interface row per MAC. Addresses are attached to the first reported MAC (or to a
 * MAC-less "unknown" interface) because an observation does not say which NIC holds which address.
 */
async function upsertInterfaces(
  tx: DbTx,
  assetId: string,
  macs: string[],
  ips: readonly string[],
): Promise<void> {
  const existing = await tx
    .select()
    .from(assetInterfaces)
    .where(eq(assetInterfaces.assetId, assetId));
  const mergeIps = async (row: (typeof existing)[number]) => {
    const merged = unique([...row.ipAddresses, ...ips]).slice(0, 64);
    if (merged.length !== row.ipAddresses.length)
      await tx
        .update(assetInterfaces)
        .set({ ipAddresses: merged })
        .where(eq(assetInterfaces.id, row.id));
  };
  if (macs.length === 0) {
    if (ips.length === 0) return;
    const anon = existing.find((i) => i.macAddress === null);
    if (anon) await mergeIps(anon);
    else
      await tx
        .insert(assetInterfaces)
        .values({ assetId, name: 'unknown', macAddress: null, ipAddresses: [...ips] });
    return;
  }
  let added = 0;
  for (const [i, mac] of macs.entries()) {
    const addrs = i === 0 ? [...ips] : [];
    const found = existing.find((e) => e.macAddress?.toLowerCase() === mac);
    if (found) {
      if (addrs.length) await mergeIps(found);
    } else {
      await tx.insert(assetInterfaces).values({
        assetId,
        name: `if${existing.length + added++}`,
        macAddress: mac,
        ipAddresses: addrs,
      });
    }
  }
}

function fillableFrom(
  attributes: Record<string, unknown>,
  current?: { [k in (typeof FILLABLE_ATTRIBUTES)[number]]: string | null } & {
    ramMb: number | null;
  },
) {
  const out: Partial<Record<(typeof FILLABLE_ATTRIBUTES)[number], string> & { ramMb: number }> = {};
  for (const key of FILLABLE_ATTRIBUTES) {
    const v = attributes[key];
    if (typeof v === 'string' && v.trim() && !(current && current[key]))
      out[key] = v.trim().slice(0, 256);
  }
  const ram = attributes['ramMb'];
  if (
    typeof ram === 'number' &&
    Number.isInteger(ram) &&
    ram >= 0 &&
    !(current && current.ramMb !== null)
  )
    out.ramMb = ram;
  return out;
}
