import { z } from 'zod';
import { Id, IpAddress, MacAddress, Port, ShortText, Timestamp } from '../common';

/** Issued by an operator for one sensor; shown once, valid for a bounded time, single use. */
export const EnrolmentTokenResponse = z.strictObject({
  sensorId: Id,
  token: z.string().min(32).max(128),
  expiresAt: Timestamp,
});
export type EnrolmentTokenResponse = z.infer<typeof EnrolmentTokenResponse>;

export const AgentPlatform = z.strictObject({
  os: ShortText,
  osVersion: ShortText.nullable().default(null),
  kernel: ShortText.nullable().default(null),
  arch: z.string().max(32),
});

export const AgentEnrolRequest = z.strictObject({
  enrolmentToken: z.string().min(32).max(128),
  hostname: ShortText,
  platform: AgentPlatform,
  agentVersion: z.string().max(64),
});
export type AgentEnrolRequest = z.infer<typeof AgentEnrolRequest>;

/** The credential is returned exactly once; only its hash is stored. */
export const AgentEnrolResponse = z.strictObject({
  sensorId: Id,
  credential: z.string().min(32).max(256),
  heartbeatIntervalSeconds: z.number().int().positive(),
});
export type AgentEnrolResponse = z.infer<typeof AgentEnrolResponse>;

export const AgentInterface = z.strictObject({
  name: z.string().min(1).max(64),
  macAddress: MacAddress.nullable().default(null),
  addresses: z.array(IpAddress).max(64).default([]),
  operState: z.enum(['up', 'down', 'unknown']).default('unknown'),
  speedMbps: z.number().int().positive().nullable().default(null),
});

export const ListeningService = z.strictObject({
  proto: z.enum(['tcp', 'udp']),
  port: Port,
  address: IpAddress.nullable().default(null),
  process: z.string().max(128).nullable().default(null),
});
export type ListeningService = z.infer<typeof ListeningService>;

export const AgentInventory = z.strictObject({
  observedAt: Timestamp,
  hostname: ShortText,
  platform: AgentPlatform,
  hardware: z.strictObject({
    manufacturer: ShortText.nullable().default(null),
    model: ShortText.nullable().default(null),
    cpuModel: ShortText.nullable().default(null),
    cpuCores: z.number().int().positive().nullable().default(null),
    ramMb: z.number().int().nonnegative().nullable().default(null),
    disks: z
      .array(
        z.strictObject({
          device: z.string().max(64),
          sizeGb: z.number().nonnegative(),
          fsType: z.string().max(32).nullable().default(null),
          mountPoint: z.string().max(256).nullable().default(null),
        }),
      )
      .max(64)
      .default([]),
    /** Only when the operator authorized serial collection on the agent side. */
    serialNumber: ShortText.nullable().default(null),
  }),
  interfaces: z.array(AgentInterface).max(128),
  listeningServices: z.array(ListeningService).max(1024).default([]),
  bootTime: Timestamp.nullable().default(null),
  agentVersion: z.string().max(64),
});
export type AgentInventory = z.infer<typeof AgentInventory>;

export const AssetServiceRecord = z.strictObject({
  proto: z.enum(['tcp', 'udp']),
  port: Port,
  address: IpAddress.nullable(),
  process: z.string().max(128).nullable(),
  source: z.string().max(128),
  firstSeenAt: Timestamp,
  lastSeenAt: Timestamp,
});
export type AssetServiceRecord = z.infer<typeof AssetServiceRecord>;

/** One passive neighbour observation (ARP/NDP table entry or DHCP lease) seen by an agent/collector. */
export const NeighborEntry = z.strictObject({
  ip: IpAddress,
  mac: MacAddress.nullable().default(null),
  source: z.enum(['arp', 'ndp', 'dhcp']),
  hostname: ShortText.nullable().default(null),
  observedAt: Timestamp,
  interface: z.string().max(64).nullable().default(null),
  vlanId: z.number().int().min(1).max(4094).nullable().default(null),
});
export type NeighborEntry = z.infer<typeof NeighborEntry>;

export const NeighborBatch = z.strictObject({ entries: z.array(NeighborEntry).min(1).max(2000) });
export type NeighborBatch = z.infer<typeof NeighborBatch>;

export const NeighborBatchResult = z.strictObject({
  received: z.number().int().nonnegative(),
  created: z.number().int().nonnegative(),
  matched: z.number().int().nonnegative(),
  ambiguous: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
});
export type NeighborBatchResult = z.infer<typeof NeighborBatchResult>;
