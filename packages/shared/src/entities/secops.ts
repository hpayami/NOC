import { z } from 'zod';
import { Id, IpAddress, LongText, Port, Sha256, ShortText, Timestamp } from '../common';
import {
  AlertStatus,
  Confidence,
  EventCategory,
  EventSourceProduct,
  FindingStatus,
  IncidentStatus,
  IncidentType,
  IndicatorKind,
  RemediationStatus,
  RuleLifecycle,
  RuleSource,
  Severity,
} from '../enums';

export const EventSchemaVersion = '1.0' as const;

export const EvidenceRef = z.strictObject({
  kind: z.enum(['event', 'pcap_slice', 'log_excerpt', 'file_hash', 'screenshot', 'note']),
  ref: z.string().max(512),
  sha256: Sha256.optional(),
});
export type EvidenceRef = z.infer<typeof EvidenceRef>;

/** Pointer to retained original data; raw payloads are never embedded in the envelope. */
export const OriginalEventRef = z.strictObject({
  store: z.string().max(64),
  key: z.string().max(512),
  sha256: Sha256.optional(),
});

/**
 * Versioned normalized event envelope (v1). Engine-specific fields live in `engine`, which is
 * size-bounded and never interpreted by shared code.
 */
export const NormalizedEvent = z.strictObject({
  schemaVersion: z.literal(EventSchemaVersion),
  eventId: Id,
  eventTime: Timestamp,
  ingestTime: Timestamp,
  sourceProduct: EventSourceProduct,
  sourceSensorId: Id.nullable(),
  category: EventCategory,
  type: z.string().min(1).max(64),
  severity: Severity,
  confidence: Confidence,
  srcAssetId: Id.nullable(),
  dstAssetId: Id.nullable(),
  srcIp: IpAddress.nullable(),
  dstIp: IpAddress.nullable(),
  srcPort: Port.nullable(),
  dstPort: Port.nullable(),
  protocol: z.string().max(32).nullable(),
  ruleId: z.string().max(128).nullable(),
  threatClassification: z
    .array(z.string().regex(/^(T\d{4}(\.\d{3})?|CWE-\d+|CVE-\d{4}-\d{4,})$/))
    .max(16),
  incidentId: Id.nullable(),
  evidenceRefs: z.array(EvidenceRef).max(32),
  correlationIds: z.array(z.string().max(128)).max(16),
  originalRef: OriginalEventRef.nullable(),
  engine: z.record(z.string(), z.unknown()).refine((v) => JSON.stringify(v).length <= 16_384, {
    message: 'engine-specific fields exceed 16 KiB',
  }),
});
export type NormalizedEvent = z.infer<typeof NormalizedEvent>;

export const NetworkFlow = z.strictObject({
  flowId: z.string().max(128),
  startTime: Timestamp,
  endTime: Timestamp.nullable(),
  sourceSensorId: Id.nullable(),
  srcIp: IpAddress,
  dstIp: IpAddress,
  srcPort: Port.nullable(),
  dstPort: Port.nullable(),
  protocol: z.string().max(32),
  bytesToServer: z.number().int().nonnegative().nullable(),
  bytesToClient: z.number().int().nonnegative().nullable(),
  packetsToServer: z.number().int().nonnegative().nullable(),
  packetsToClient: z.number().int().nonnegative().nullable(),
  appProtocol: z.string().max(32).nullable(),
});
export type NetworkFlow = z.infer<typeof NetworkFlow>;

export const Alert = z.strictObject({
  id: Id,
  title: ShortText,
  status: AlertStatus,
  severity: Severity,
  confidence: Confidence,
  priorityScore: z.number().min(0).max(100),
  ruleId: Id.nullable(),
  sourceProduct: EventSourceProduct,
  assetId: Id.nullable(),
  dedupKey: z.string().max(256),
  occurrenceCount: z.number().int().positive(),
  firstSeenAt: Timestamp,
  lastSeenAt: Timestamp,
  assigneeId: Id.nullable(),
  incidentId: Id.nullable(),
  suppressedUntil: Timestamp.nullable(),
  dispositionNote: LongText.nullable(),
});
export type Alert = z.infer<typeof Alert>;

export const Incident = z.strictObject({
  id: Id,
  title: ShortText,
  type: IncidentType,
  status: IncidentStatus,
  severity: Severity,
  assigneeId: Id.nullable(),
  commanderId: Id.nullable(),
  summary: LongText,
  openedAt: Timestamp,
  closedAt: Timestamp.nullable(),
  closureReason: LongText.nullable(),
});
export type Incident = z.infer<typeof Incident>;

export const DetectionRule = z.strictObject({
  id: Id,
  source: RuleSource,
  externalId: z.string().max(128),
  revision: z.number().int().positive(),
  name: ShortText,
  lifecycle: RuleLifecycle,
  severity: Severity,
  attackTechniques: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).max(16),
  license: z.string().max(128).nullable(),
  contentSha256: Sha256,
  validatedAt: Timestamp.nullable(),
  deployedAt: Timestamp.nullable(),
});
export type DetectionRule = z.infer<typeof DetectionRule>;

export const ThreatIndicator = z.strictObject({
  id: Id,
  kind: IndicatorKind,
  value: z.string().min(1).max(2048),
  source: z.string().max(128),
  confidence: Confidence,
  validFrom: Timestamp,
  validUntil: Timestamp.nullable(),
  tlp: z.enum(['clear', 'green', 'amber', 'amber_strict', 'red']),
});
export type ThreatIndicator = z.infer<typeof ThreatIndicator>;

export const VulnerabilityFinding = z.strictObject({
  id: Id,
  assetId: Id,
  engagementId: Id.nullable(),
  title: ShortText,
  status: FindingStatus,
  severity: Severity,
  cve: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/)).max(32),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).max(16),
  /** CVSS is one input to risk, not a risk score; business risk is derived separately. */
  cvssBaseScore: z.number().min(0).max(10).nullable(),
  cvssVector: z.string().max(256).nullable(),
  validated: z.boolean(),
  evidenceRefs: z.array(EvidenceRef).max(32),
  firstDetectedAt: Timestamp,
  lastDetectedAt: Timestamp,
});
export type VulnerabilityFinding = z.infer<typeof VulnerabilityFinding>;

export const RemediationTask = z.strictObject({
  id: Id,
  findingId: Id.nullable(),
  incidentId: Id.nullable(),
  title: ShortText,
  status: RemediationStatus,
  assigneeId: Id.nullable(),
  dueAt: Timestamp.nullable(),
  verifiedAt: Timestamp.nullable(),
});
export type RemediationTask = z.infer<typeof RemediationTask>;

export const MlInferenceResult = z.strictObject({
  id: Id,
  modelName: ShortText,
  modelVersion: z.string().max(64),
  featureSetVersion: z.string().max(64),
  subjectType: z.enum(['asset', 'flow', 'alert', 'dns_query']),
  subjectId: z.string().max(128),
  score: z.number().min(0).max(1),
  /** ML output is advisory only and can never directly trigger enforcement. */
  advisory: z.literal(true),
  explanation: z
    .array(z.strictObject({ feature: z.string().max(64), contribution: z.number() }))
    .max(32),
  evidenceRefs: z.array(EvidenceRef).max(32),
  createdAt: Timestamp,
});
export type MlInferenceResult = z.infer<typeof MlInferenceResult>;
