import { z } from 'zod';
import { Id, IpAddress, MacAddress, ShortText, Timestamp } from '../common';

/**
 * A normalized SNMPv3 walk produced by a collector. The management plane never speaks SNMP
 * itself: collectors hold the credentials, poll inside their segment and push snapshots.
 */
export const SnmpInterface = z.strictObject({
  ifIndex: z.number().int().positive(),
  ifName: z.string().min(1).max(64),
  ifDescr: z.string().max(256).nullable().default(null),
  ifType: z.number().int().nonnegative().nullable().default(null),
  ifMtu: z.number().int().nonnegative().nullable().default(null),
  ifSpeedBps: z.number().int().nonnegative().nullable().default(null),
  ifPhysAddress: MacAddress.nullable().default(null),
  ifAdminStatus: z.enum(['up', 'down', 'testing', 'unknown']).default('unknown'),
  ifOperStatus: z
    .enum(['up', 'down', 'testing', 'unknown', 'dormant', 'notPresent', 'lowerLayerDown'])
    .default('unknown'),
  ifHCInOctets: z.number().int().nonnegative().nullable().default(null),
  ifHCOutOctets: z.number().int().nonnegative().nullable().default(null),
  ifInErrors: z.number().int().nonnegative().nullable().default(null),
  ifOutErrors: z.number().int().nonnegative().nullable().default(null),
  ifInDiscards: z.number().int().nonnegative().nullable().default(null),
  ifOutDiscards: z.number().int().nonnegative().nullable().default(null),
  addresses: z.array(IpAddress).max(32).default([]),
});
export type SnmpInterface = z.infer<typeof SnmpInterface>;

export const LldpNeighbor = z.strictObject({
  localIfIndex: z.number().int().positive(),
  /** lldpRemChassisIdSubtype: 4 = macAddress, 5 = networkAddress, 7 = local. */
  remoteChassisIdSubtype: z.number().int().min(1).max(7),
  remoteChassisId: z.string().min(1).max(128),
  remotePortId: z.string().max(128).nullable().default(null),
  remoteSysName: z.string().max(256).nullable().default(null),
});
export type LldpNeighbor = z.infer<typeof LldpNeighbor>;

export const SnmpSnapshot = z.strictObject({
  collectorId: Id,
  observedAt: Timestamp,
  agentAddress: IpAddress,
  system: z.strictObject({
    sysName: ShortText.nullable(),
    sysDescr: z.string().max(1024).nullable(),
    sysObjectId: z.string().max(128).nullable(),
    sysUpTimeSeconds: z.number().int().nonnegative().nullable(),
    sysLocation: z.string().max(256).nullable().default(null),
    sysContact: z.string().max(256).nullable().default(null),
  }),
  interfaces: z.array(SnmpInterface).max(1024),
  lldpNeighbors: z.array(LldpNeighbor).max(1024).default([]),
});
export type SnmpSnapshot = z.infer<typeof SnmpSnapshot>;

export const SnmpSnapshotResult = z.strictObject({
  assetId: Id.nullable(),
  decision: z.enum(['match', 'create', 'ambiguous']),
  interfacesUpserted: z.number().int().nonnegative(),
  metricsStored: z.number().int().nonnegative(),
  lldp: z.strictObject({
    resolved: z.number().int().nonnegative(),
    unresolved: z.number().int().nonnegative(),
  }),
});
export type SnmpSnapshotResult = z.infer<typeof SnmpSnapshotResult>;
