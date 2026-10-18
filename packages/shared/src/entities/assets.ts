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
  Severity,
} from '../enums';
import { FindingRecord } from './assessments';

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
  /** Derived from interfaces for display; never an identity. */
  ipAddresses: z.array(IpAddress).max(64),
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

// ---- Dependency graph and per-asset risk profile (Phase 1 follow-up) ------------------------

export const RiskLevel = z.enum(['critical', 'high', 'medium', 'low', 'none', 'unknown']);
export type RiskLevel = z.infer<typeof RiskLevel>;

export const AssetRisk = z.strictObject({
  level: RiskLevel,
  score: z.number().int().min(0).max(100),
  confidence: z.enum(['high', 'medium', 'low']),
  basis: z.array(z.string().max(512)).max(16),
});
export type AssetRisk = z.infer<typeof AssetRisk>;

export const AssetGraphNode = z.strictObject({
  id: Id,
  label: ShortText,
  hostname: ShortText.nullable(),
  ipAddresses: z.array(IpAddress).max(8),
  assetClass: AssetClass,
  segmentId: Id.nullable(),
  site: ShortText.nullable(),
  criticality: Criticality,
  operationalStatus: OperationalStatus,
  monitoringCoverage: CoverageState,
  assuranceState: AssuranceState,
  risk: AssetRisk,
  openFindings: z.number().int().nonnegative(),
  openAlerts: z.number().int().nonnegative(),
  openPorts: z.number().int().nonnegative(),
});
export type AssetGraphNode = z.infer<typeof AssetGraphNode>;

/**
 * An edge exists only with evidence: a recorded topology relationship, or traffic the sensors
 * actually saw between the two assets inside the window. Nothing is inferred from addresses.
 */
export const AssetGraphEdge = z.strictObject({
  id: z.string().max(128),
  sourceAssetId: Id,
  targetAssetId: Id,
  kind: RelationshipKind,
  basis: z.enum(['topology', 'observed_traffic']),
  verification: RelationshipVerification,
  evidence: z.string().max(1024),
  /** Topology: 1. Observed traffic: number of events in the window. */
  weight: z.number().int().positive(),
  ports: z.array(z.number().int().min(0).max(65535)).max(16),
  lastObservedAt: Timestamp,
});
export type AssetGraphEdge = z.infer<typeof AssetGraphEdge>;

export const AssetGraph = z.strictObject({
  nodes: z.array(AssetGraphNode).max(2000),
  edges: z.array(AssetGraphEdge).max(10000),
  window: z.strictObject({ from: Timestamp, to: Timestamp }),
  truncated: z.boolean(),
  generatedAt: Timestamp,
});
export type AssetGraph = z.infer<typeof AssetGraph>;

export const AssetGraphQuery = z.strictObject({
  /** Traffic window for observed_traffic edges, in hours. */
  hours: z.coerce.number().int().min(1).max(720).default(168),
  limit: z.coerce.number().int().min(1).max(2000).default(500),
});

export const AssetOpenPort = z.strictObject({
  proto: z.enum(['tcp', 'udp']),
  port: z.number().int().min(0).max(65535),
  /** Known service name for risky ports; null when the platform has no opinion. */
  service: ShortText.nullable(),
  severity: Severity.nullable(),
  why: ShortText.nullable(),
  /** Who reported it: endpoint agent inventory, assessment run, discovery job. */
  source: z.string().max(128),
  lastSeenAt: Timestamp,
});
export type AssetOpenPort = z.infer<typeof AssetOpenPort>;

export const AssetTechnique = z.strictObject({
  techniqueId: z.string().regex(/^T\d{4}(\.\d{3})?$/),
  name: ShortText.nullable(),
  tactic: ShortText.nullable(),
  /** `alert`: a detection fired against this asset; `exposure`: an open service makes it available. */
  source: z.enum(['alert', 'exposure']),
  evidence: z.string().max(512),
  count: z.number().int().positive(),
});
export type AssetTechnique = z.infer<typeof AssetTechnique>;

export const AssetRiskAlert = z.strictObject({
  id: Id,
  title: ShortText,
  severity: Severity,
  status: z.string().max(32),
  lastSeenAt: Timestamp,
  occurrenceCount: z.number().int().positive(),
  techniques: z.array(z.string().max(16)).max(16),
});

export const AssetRiskNeighbor = z.strictObject({
  assetId: Id,
  label: ShortText,
  kind: RelationshipKind,
  basis: z.enum(['topology', 'observed_traffic']),
  direction: z.enum(['in', 'out', 'both']),
  weight: z.number().int().positive(),
});

export const AssetRiskProfile = z.strictObject({
  asset: Asset,
  site: ShortText.nullable(),
  risk: AssetRisk,
  openPorts: z.array(AssetOpenPort).max(500),
  techniques: z.array(AssetTechnique).max(64),
  alerts: z.array(AssetRiskAlert).max(50),
  alertsIncluded: z.boolean(),
  /** Findings need findings.read; otherwise empty and findingsIncluded=false. */
  findings: z.array(FindingRecord).max(200),
  findingsIncluded: z.boolean(),
  neighbors: z.array(AssetRiskNeighbor).max(100),
  generatedAt: Timestamp,
});
export type AssetRiskProfile = z.infer<typeof AssetRiskProfile>;
