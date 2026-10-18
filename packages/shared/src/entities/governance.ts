import { z } from 'zod';
import { Cidr, Id, IpAddress, LongText, ShortText, Timestamp } from '../common';
import {
  AssessmentTechnique,
  EngagementStatus,
  ResponseActionKind,
  ResponseActionStatus,
} from '../enums';

export const AuthorizedTargetScope = z.strictObject({
  includeCidrs: z.array(Cidr).max(256),
  includeAddresses: z.array(IpAddress).max(1024),
  excludeCidrs: z.array(Cidr).max(256),
  excludeAddresses: z.array(IpAddress).max(1024),
  /** Public (non-RFC1918/ULA) targets are refused unless explicitly acknowledged here. */
  allowPublicAddresses: z.boolean().default(false),
  allowedTechniques: z.array(AssessmentTechnique).min(1),
  windowStart: Timestamp,
  windowEnd: Timestamp,
  maxConcurrency: z.number().int().min(1).max(64),
  maxRequestsPerSecond: z.number().min(0.1).max(1000),
});
export type AuthorizedTargetScope = z.infer<typeof AuthorizedTargetScope>;

export const AssessmentEngagement = z.strictObject({
  id: Id,
  reference: ShortText,
  authorizingOrganization: ShortText,
  responsibleOperatorId: Id,
  authorizationReference: ShortText,
  status: EngagementStatus,
  scope: AuthorizedTargetScope,
  dataHandlingRestrictions: LongText,
  stopConditions: z.array(z.string().max(512)).min(1),
  emergencyContact: ShortText,
  evidenceRetentionDays: z.number().int().min(1).max(3650),
  createdAt: Timestamp,
});
export type AssessmentEngagement = z.infer<typeof AssessmentEngagement>;

export const ResponseAction = z.strictObject({
  id: Id,
  kind: ResponseActionKind,
  status: ResponseActionStatus,
  incidentId: Id.nullable(),
  targetType: z.string().max(64),
  targetRef: z.string().max(512),
  triggeringEvidence: z.array(z.string().max(512)).max(32),
  proposedBy: Id,
  /** `recommended` actions have changed nothing. Only `executed` actions altered production state. */
  executedAt: Timestamp.nullable(),
  expiresAt: Timestamp.nullable(),
  rollbackPlan: LongText,
  rolledBackAt: Timestamp.nullable(),
  verificationResult: z.enum(['not_run', 'passed', 'failed']),
});
export type ResponseAction = z.infer<typeof ResponseAction>;

export const MonitoringPolicy = z.strictObject({
  id: Id,
  name: ShortText,
  assetClasses: z.array(z.string()).max(32),
  metricIntervalSeconds: z.number().int().min(10).max(86_400),
  heartbeatTimeoutSeconds: z.number().int().min(10).max(86_400),
  maxEventLagSeconds: z.number().int().min(1).max(86_400),
  enabled: z.boolean(),
});
export type MonitoringPolicy = z.infer<typeof MonitoringPolicy>;

export const RetentionPolicy = z.strictObject({
  id: Id,
  dataClass: z.enum([
    'security_events',
    'raw_events',
    'flows',
    'audit',
    'evidence',
    'metrics',
    'pcap',
  ]),
  retentionDays: z.number().int().min(1).max(3650),
  /** Audit retention may never be shorter than the platform floor (enforced in the API). */
  legalHold: z.boolean(),
  updatedAt: Timestamp,
});
export type RetentionPolicy = z.infer<typeof RetentionPolicy>;
