import { z } from 'zod';
import { Id, IpAddress, LongText, Port, ShortText, Timestamp } from '../common';
import {
  ApprovalDecision,
  AssessmentTechnique,
  EngagementStatus,
  FindingStatus,
  Severity,
} from '../enums';
import { AuthorizedTargetScope } from './governance';
import { VulnerabilityFinding } from './secops';
import { VulnerabilityRecord } from './vulnerabilities';

export const CreateEngagementRequest = z.strictObject({
  reference: ShortText,
  authorizingOrganization: ShortText,
  /** Ticket / contract / written authorisation identifier. Mandatory: no authorisation, no engagement. */
  authorizationReference: ShortText,
  objective: z.string().trim().min(10).max(4096),
  scope: AuthorizedTargetScope,
  dataHandlingRestrictions: LongText.default(''),
  stopConditions: z.array(z.string().trim().min(1).max(512)).min(1).max(32),
  emergencyContact: ShortText,
  evidenceRetentionDays: z.number().int().min(1).max(3650).default(365),
});
export type CreateEngagementRequest = z.infer<typeof CreateEngagementRequest>;

export const EngagementScopeUpdateRequest = z.strictObject({
  scope: AuthorizedTargetScope,
  reason: z.string().trim().min(10).max(2048),
});
export type EngagementScopeUpdateRequest = z.infer<typeof EngagementScopeUpdateRequest>;

export const EngagementDecisionRequest = z.strictObject({
  justification: z.string().trim().min(10).max(4096),
});
export const EngagementTransitionRequest = z.strictObject({
  to: EngagementStatus.extract(['pending_approval', 'active', 'paused', 'completed', 'cancelled']),
  reason: z.string().trim().max(2048).optional(),
});
export type EngagementTransitionRequest = z.infer<typeof EngagementTransitionRequest>;

export const EngagementApproval = z.strictObject({
  approverId: Id,
  decision: ApprovalDecision,
  justification: LongText,
  decidedAt: Timestamp,
  scopeVersion: z.number().int().positive(),
});

export const EngagementRecord = z.strictObject({
  id: Id,
  reference: ShortText,
  authorizingOrganization: ShortText,
  authorizationReference: ShortText,
  objective: LongText,
  status: EngagementStatus,
  responsibleOperatorId: Id,
  scope: AuthorizedTargetScope,
  scopeVersion: z.number().int().positive(),
  /** Scope version the current approval covers; differs from scopeVersion after a scope change. */
  approvedScopeVersion: z.number().int().positive().nullable(),
  approvals: z.array(EngagementApproval),
  dataHandlingRestrictions: LongText,
  stopConditions: z.array(z.string().max(512)),
  emergencyContact: ShortText,
  evidenceRetentionDays: z.number().int().min(1).max(3650),
  activatedAt: Timestamp.nullable(),
  completedAt: Timestamp.nullable(),
  closeReason: LongText.nullable(),
  runCount: z.number().int().nonnegative(),
  findingCount: z.number().int().nonnegative(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type EngagementRecord = z.infer<typeof EngagementRecord>;

export const EngagementListQuery = z.strictObject({
  status: EngagementStatus.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/** Connect-level techniques the platform executes itself. Everything else needs an external worker. */
export const EXECUTABLE_TECHNIQUES: readonly AssessmentTechnique[] = [
  'host_discovery',
  'service_fingerprint',
];

export const DEFAULT_ASSESSMENT_PORTS = [
  21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200,
  11211, 27017,
] as const;

export const CreateRunRequest = z.strictObject({
  technique: AssessmentTechnique,
  /** Dry runs evaluate scope decisions per target and send nothing. Default for new runs. */
  dryRun: z.boolean().default(true),
  ports: z
    .array(Port)
    .min(1)
    .max(32)
    .default([...DEFAULT_ASSESSMENT_PORTS]),
  note: z.string().trim().max(2048).optional(),
});
export type CreateRunRequest = z.infer<typeof CreateRunRequest>;

export const RunStatusValues = ['queued', 'running', 'completed', 'cancelled', 'failed'] as const;
export const RunStatus = z.enum(RunStatusValues);
export type RunStatus = z.infer<typeof RunStatus>;

export const RunSummary = z.strictObject({
  allowed: z.number().int().nonnegative(),
  denied: z.number().int().nonnegative(),
  reachable: z.number().int().nonnegative(),
  unreachable: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
  findingsCreated: z.number().int().nonnegative(),
  findingsUpdated: z.number().int().nonnegative(),
});
export type RunSummary = z.infer<typeof RunSummary>;

export const AssessmentRun = z.strictObject({
  id: Id,
  engagementId: Id,
  scopeVersion: z.number().int().positive(),
  technique: AssessmentTechnique,
  status: RunStatus,
  dryRun: z.boolean(),
  ports: z.array(Port),
  requestedBy: Id,
  note: z.string().max(2048).nullable(),
  targetCount: z.number().int().nonnegative(),
  startedAt: Timestamp.nullable(),
  finishedAt: Timestamp.nullable(),
  summary: RunSummary.nullable(),
  createdAt: Timestamp,
});
export type AssessmentRun = z.infer<typeof AssessmentRun>;

export const RunTarget = z.strictObject({
  target: IpAddress,
  decision: z.enum(['pending', 'allowed', 'denied']),
  reasons: z.array(z.string().max(256)).max(16),
  outcome: z.enum(['pending', 'reachable', 'unreachable', 'skipped']),
  openPorts: z.array(Port).max(32),
  observedAt: Timestamp.nullable(),
});
export type RunTarget = z.infer<typeof RunTarget>;

export const FindingRecord = VulnerabilityFinding.extend({
  description: LongText,
  lastNote: LongText.nullable(),
  updatedAt: Timestamp,
  /** Catalogue entries for the finding's CVE ids (empty when the catalogue has none of them). */
  vulnerabilities: z.array(VulnerabilityRecord).max(32),
});
export type FindingRecord = z.infer<typeof FindingRecord>;

/** What the platform can honestly say about one in-scope address. */
export const TargetCoverageStatusValues = [
  'assessed_with_findings',
  'assessed_no_findings',
  'unreachable',
  'denied',
  'not_assessed',
] as const;
export const TargetCoverageStatus = z.enum(TargetCoverageStatusValues);
export type TargetCoverageStatus = z.infer<typeof TargetCoverageStatus>;

export const TargetCoverage = z.strictObject({
  target: IpAddress,
  status: TargetCoverageStatus,
  /** Techniques that actually probed this address (live runs only). */
  techniques: z.array(AssessmentTechnique),
  openPorts: z.array(Port).max(64),
  findingCount: z.number().int().nonnegative(),
  reasons: z.array(z.string().max(256)).max(16),
  lastObservedAt: Timestamp.nullable(),
  /** Address was probed by a run but is not in the current scope version. */
  outsideCurrentScope: z.boolean(),
});
export type TargetCoverage = z.infer<typeof TargetCoverage>;

export const TechniqueCoverage = z.strictObject({
  technique: AssessmentTechnique,
  executable: z.boolean(),
  liveRuns: z.number().int().nonnegative(),
  dryRuns: z.number().int().nonnegative(),
  status: z.enum(['performed', 'dry_run_only', 'not_performed', 'not_executable']),
});
export type TechniqueCoverage = z.infer<typeof TechniqueCoverage>;

export const CoverageSummary = z.strictObject({
  targetsInScope: z.number().int().nonnegative(),
  assessedWithFindings: z.number().int().nonnegative(),
  assessedNoFindings: z.number().int().nonnegative(),
  unreachable: z.number().int().nonnegative(),
  denied: z.number().int().nonnegative(),
  notAssessed: z.number().int().nonnegative(),
  /** Scope enumeration or the target table hit a bound; counts above are of what was listed. */
  truncated: z.boolean(),
});
export type CoverageSummary = z.infer<typeof CoverageSummary>;

/**
 * Engagement report: everything the platform knows, plus everything it does not. `limitations`
 * is part of the contract so a report can never silently read as "the network was assessed".
 */
export const EngagementReport = z.strictObject({
  generatedAt: Timestamp,
  generatedBy: Id,
  engagement: EngagementRecord,
  techniques: z.array(TechniqueCoverage),
  runs: z.array(AssessmentRun),
  coverage: CoverageSummary,
  targets: z.array(TargetCoverage).max(5000),
  /** Present only when the requester holds findings.read (see limitations otherwise). */
  findings: z.array(FindingRecord),
  findingsIncluded: z.boolean(),
  limitations: z.array(z.string().max(512)),
});
export type EngagementReport = z.infer<typeof EngagementReport>;

export const ReportFormatQuery = z.strictObject({
  format: z.enum(['json', 'markdown']).default('json'),
});

export const RunDetail = z.strictObject({
  run: AssessmentRun,
  targets: z.array(RunTarget),
  findings: z.array(FindingRecord),
});
export type RunDetail = z.infer<typeof RunDetail>;

export const TechniqueInfo = z.strictObject({
  technique: AssessmentTechnique,
  executable: z.boolean(),
  description: z.string().max(512),
});

export const FindingUpdateRequest = z.strictObject({
  status: FindingStatus,
  note: z.string().trim().min(5).max(4096),
});
export type FindingUpdateRequest = z.infer<typeof FindingUpdateRequest>;

export const FindingListQuery = z.strictObject({
  engagementId: Id.optional(),
  assetId: Id.optional(),
  status: FindingStatus.optional(),
  severity: Severity.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
