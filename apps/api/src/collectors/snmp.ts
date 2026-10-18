import { and, eq, inArray, sql } from 'drizzle-orm';
import type { SnmpSnapshot, SnmpSnapshotResult } from '@noc/shared';
import type { AssetService, IngestActor } from '../assets/service';
import type { Db } from '../db/client';
import { assetInterfaces, assetMetrics, assets, topologyRelationships } from '../db/schema';

/** Interface counters mapped to metric names; the ifIndex keeps the series stable across renames. */
const COUNTERS = [
  ['ifHCInOctets', 'in_octets', 'B'],
  ['ifHCOutOctets', 'out_octets', 'B'],
  ['ifInErrors', 'in_errors', null],
  ['ifOutErrors', 'out_errors', null],
  ['ifInDiscards', 'in_discards', null],
  ['ifOutDiscards', 'out_discards', null],
] as const;

const adminState = (s: string) => (s === 'up' || s === 'down' ? s : 'unknown');
const operState = (s: string) =>
  s === 'up'
    ? 'up'
    : s === 'down' || s === 'lowerLayerDown' || s === 'notPresent'
      ? 'down'
      : 'unknown';

/**
 * Applies a collector's SNMPv3 snapshot: one observation (identity resolution as usual), one
 * interface row per ifName, counters as metrics, and LLDP neighbours as *verified* layer-2 edges
 * when the neighbour resolves to a known asset. Unresolved neighbours are counted, never invented.
 */
export async function applySnmpSnapshot(
  db: Db,
  assetsSvc: AssetService,
  snap: SnmpSnapshot,
  actor: IngestActor,
): Promise<SnmpSnapshotResult> {
  const macs = [
    ...new Set(snap.interfaces.map((i) => i.ifPhysAddress).filter((m): m is string => !!m)),
  ].filter((m) => m !== '00:00:00:00:00:00');
  const ips = [...new Set([snap.agentAddress, ...snap.interfaces.flatMap((i) => i.addresses)])];
  const ingest = await assetsSvc.ingest(
    {
      source: `snmp:${snap.collectorId}`,
      method: 'snmpv3',
      observedAt: snap.observedAt,
      identifiers: {
        macAddresses: macs,
        ipAddresses: ips,
        hostnames: snap.system.sysName ? [snap.system.sysName] : [],
      },
      attributes: {
        'snmp.sysDescr': snap.system.sysDescr,
        'snmp.sysObjectId': snap.system.sysObjectId,
        'snmp.sysLocation': snap.system.sysLocation,
        'snmp.sysUpTimeSeconds': snap.system.sysUpTimeSeconds,
        'snmp.interfaceCount': snap.interfaces.length,
      },
    },
    actor,
  );
  if (!ingest.assetId)
    return {
      assetId: null,
      decision: 'ambiguous',
      interfacesUpserted: 0,
      metricsStored: 0,
      lldp: { resolved: 0, unresolved: snap.lldpNeighbors.length },
    };
  const assetId = ingest.assetId;
  const observedAt = new Date(snap.observedAt);

  return db.transaction(async (tx) => {
    // Interfaces keyed by name; SNMP gives per-interface addresses, unlike generic observations.
    const existing = await tx
      .select()
      .from(assetInterfaces)
      .where(eq(assetInterfaces.assetId, assetId));
    const byName = new Map(existing.map((e) => [e.name, e]));
    const byMac = new Map(
      existing.filter((e) => e.macAddress).map((e) => [e.macAddress!.toLowerCase(), e]),
    );
    const ifaceIdByIndex = new Map<number, string>();
    for (const i of snap.interfaces) {
      const mac =
        i.ifPhysAddress && i.ifPhysAddress !== '00:00:00:00:00:00' ? i.ifPhysAddress : null;
      const row = byName.get(i.ifName) ?? (mac ? byMac.get(mac) : undefined);
      const values = {
        name: i.ifName,
        macAddress: mac,
        ipAddresses: i.addresses,
        speedMbps: i.ifSpeedBps !== null ? Math.round(i.ifSpeedBps / 1_000_000) : null,
        adminState: adminState(i.ifAdminStatus),
        operState: operState(i.ifOperStatus),
      };
      if (row) {
        await tx.update(assetInterfaces).set(values).where(eq(assetInterfaces.id, row.id));
        ifaceIdByIndex.set(i.ifIndex, row.id);
      } else {
        const [created] = await tx
          .insert(assetInterfaces)
          .values({ assetId, ...values })
          .returning({ id: assetInterfaces.id });
        ifaceIdByIndex.set(i.ifIndex, created!.id);
      }
    }

    const points: (typeof assetMetrics.$inferInsert)[] = [];
    if (snap.system.sysUpTimeSeconds !== null)
      points.push({
        assetId,
        metric: 'sys.uptime_seconds',
        observedAt,
        value: snap.system.sysUpTimeSeconds,
        unit: 's',
        source: `snmp:${snap.collectorId}`,
      });
    for (const i of snap.interfaces) {
      for (const [field, name, unit] of COUNTERS) {
        const v = i[field];
        if (v !== null)
          points.push({
            assetId,
            metric: `if.${i.ifIndex}.${name}`,
            observedAt,
            value: v,
            unit,
            source: `snmp:${snap.collectorId}`,
          });
      }
      if (i.ifOperStatus !== 'unknown')
        points.push({
          assetId,
          metric: `if.${i.ifIndex}.oper_up`,
          observedAt,
          value: i.ifOperStatus === 'up' ? 1 : 0,
          unit: null,
          source: `snmp:${snap.collectorId}`,
        });
    }
    if (points.length) await tx.insert(assetMetrics).values(points);

    // LLDP → verified L2 adjacency when the neighbour is a known asset (by chassis MAC, else by unique sysName).
    let resolved = 0;
    let unresolved = 0;
    for (const n of snap.lldpNeighbors) {
      let remoteAssetId: string | null = null;
      if (
        n.remoteChassisIdSubtype === 4 &&
        /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(n.remoteChassisId)
      ) {
        const [hit] = await tx
          .select({ assetId: assetInterfaces.assetId })
          .from(assetInterfaces)
          .where(sql`${assetInterfaces.macAddress} = ${n.remoteChassisId.toLowerCase()}::macaddr`)
          .limit(1);
        remoteAssetId = hit?.assetId ?? null;
      }
      if (!remoteAssetId && n.remoteSysName) {
        const hits = await tx
          .select({ id: assets.id })
          .from(assets)
          .where(sql`lower(${assets.hostname}) = lower(${n.remoteSysName})`)
          .limit(2);
        if (hits.length === 1) remoteAssetId = hits[0]!.id;
      }
      if (!remoteAssetId || remoteAssetId === assetId) {
        unresolved++;
        continue;
      }
      resolved++;
      const sourceInterfaceId = ifaceIdByIndex.get(n.localIfIndex) ?? null;
      const evidence = `LLDP-MIB lldpRemTable via collector ${snap.collectorId}: ${n.remoteChassisId}${n.remotePortId ? ' port ' + n.remotePortId : ''}`;
      const [edge] = await tx
        .select({ id: topologyRelationships.id })
        .from(topologyRelationships)
        .where(
          and(
            eq(topologyRelationships.kind, 'layer2_adjacency'),
            eq(topologyRelationships.sourceAssetId, assetId),
            eq(topologyRelationships.targetAssetId, remoteAssetId),
            sourceInterfaceId
              ? eq(topologyRelationships.sourceInterfaceId, sourceInterfaceId)
              : sql`${topologyRelationships.sourceInterfaceId} is null`,
          ),
        )
        .limit(1);
      if (edge)
        await tx
          .update(topologyRelationships)
          .set({ lastObservedAt: observedAt, evidence, verification: 'verified' })
          .where(eq(topologyRelationships.id, edge.id));
      else
        await tx.insert(topologyRelationships).values({
          kind: 'layer2_adjacency',
          sourceAssetId: assetId,
          targetAssetId: remoteAssetId,
          sourceInterfaceId,
          targetInterfaceId: null,
          verification: 'verified',
          evidence,
          firstObservedAt: observedAt,
          lastObservedAt: observedAt,
        });
    }
    return {
      assetId,
      decision: ingest.decision.action,
      interfacesUpserted: snap.interfaces.length,
      metricsStored: points.length,
      lldp: { resolved, unresolved },
    };
  });
}

export { inArray };
