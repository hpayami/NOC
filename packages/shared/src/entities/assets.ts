import { z } from 'zod';
import {
  Cidr,
  Id,
  IpAddress,
  LongText,
  MacAddress,
  Provenance,
  ShortText,
  Timestamp,
} from '../common';
import {
  AssetClass,
  AssuranceState,
  CoverageState,
  Criticality,
  DiscoveryMethod,
  OperationalStatus,
  RelationshipKind,
  RelationshipVerification,
} from '../enums';

export const AssetInterface = z.strictObject({
  id: Id,
  assetId: Id,
  name: ShortText,
  macAddress: MacAddress.nullable(),
  ipAddresses: z.array(IpAddress).max(64),
  speedMbps: z.number().int().positive().nullable(),
  adminState: z.enum(['up', 'down', 'unknown']),
  operState: z.enum(['up', 'down', 'unknown']),
  vlanId: z.number().int().min(1).max(4094).nullable(),
});
export type AssetInterface = z.infer<typeof AssetInterface>;

/**
 * Public asset. `serialNumber` is only populated for callers holding `assets.read_sensitive`
 * and only when collection was authorized; otherwise it is null.
 * IP addresses are attributes of observations, never the asset's identity.
 */
export const Asset = z.strictObject({
  id: Id,
  hostname: ShortText.nullable(),
  assetClass: AssetClass,
  manufacturer: ShortText.nullable(),
  model: ShortText.nullable(),
  serialNumber: ShortText.nullable(),
  osName: ShortText.nullable(),
  osVersion: ShortText.nullable(),
  firmwareVersion: ShortText.nullable(),
  cpuArchitecture: z.string().max(32).nullable(),
  ramMb: z.number().int().nonnegative().nullable(),
  segmentId: Id.nullable(),
  role: ShortText.nullable(),
  criticality: Criticality,
  owner: ShortText.nullable(),
  responsibleTeam: ShortText.nullable(),
  discoveryMethods: z.array(DiscoveryMethod),
  firstSeenAt: Timestamp,
  lastSeenAt: Timestamp,
  operationalStatus: OperationalStatus,
  monitoringCoverage: CoverageState,
  credentialedAssessmentStatus: z.enum(['not_performed', 'performed', 'failed', 'not_authorized']),
  assuranceState: AssuranceState,
  dataConfidence: z.number().min(0).max(1),
  provenance: z.array(Provenance).max(32),
});
export type Asset = z.infer<typeof Asset>;

/** A single point-in-time statement from one source; assets are resolved *from* observations. */
export const AssetObservation = z.strictObject({
  id: Id,
  assetId: Id.nullable(),
  source: z.string().max(128),
  method: DiscoveryMethod,
  observedAt: Timestamp,
  identifiers: z.strictObject({
    macAddresses: z.array(MacAddress).max(32).default([]),
    ipAddresses: z.array(IpAddress).max(32).default([]),
    hostnames: z.array(ShortText).max(16).default([]),
    cloudInstanceId: z.string().max(256).optional(),
    agentId: z.string().max(128).optional(),
    serialNumber: z.string().max(128).optional(),
  }),
  attributes: z.record(
    z.string(),
    z.union([z.string().max(1024), z.number(), z.boolean(), z.null()]),
  ),
  conflictsWith: z.array(Id).max(16).default([]),
});
export type AssetObservation = z.infer<typeof AssetObservation>;

export const NetworkSegment = z.strictObject({
  id: Id,
  name: ShortText,
  site: ShortText.nullable(),
  cidr: Cidr.nullable(),
  vlanId: z.number().int().min(1).max(4094).nullable(),
  /** Whether active discovery may ever touch this segment. Management networks default to false. */
  activeDiscoveryAllowed: z.boolean(),
  description: LongText.nullable(),
});
export type NetworkSegment = z.infer<typeof NetworkSegment>;

export const TopologyRelationship = z.strictObject({
  id: Id,
  kind: RelationshipKind,
  sourceAssetId: Id,
  targetAssetId: Id,
  sourceInterfaceId: Id.nullable(),
  targetInterfaceId: Id.nullable(),
  verification: RelationshipVerification,
  evidence: z.string().max(1024),
  firstObservedAt: Timestamp,
  lastObservedAt: Timestamp,
});
export type TopologyRelationship = z.infer<typeof TopologyRelationship>;
