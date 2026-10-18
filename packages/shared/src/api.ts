import { z } from 'zod';
import { AssetServiceRecord } from './entities/agents';
import { Id, PageQuery, ShortText, Timestamp } from './common';
import {
  AssetClass,
  AssuranceState,
  AssuranceStateValues,
  CoverageState,
  Criticality,
  OperationalStatus,
} from './enums';
import {
  Asset,
  AssetInterface,
  AssetObservation,
  NetworkSegment,
  TopologyRelationship,
} from './entities/assets';
import { PermissionSchema, RoleKeySchema } from './rbac';
import { User } from './entities/identity';

/** Password policy shared by API validation and the web form hints (length-first, per NIST 800-63B). */
export const PASSWORD_MIN_LENGTH = 14;
export const PASSWORD_MAX_LENGTH = 256;
export const Password = z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH);

export const LoginRequest = z.strictObject({
  email: z.email().max(254),
  password: z.string().min(1).max(PASSWORD_MAX_LENGTH),
});
export type LoginRequest = z.infer<typeof LoginRequest>;

export const SessionUser = z.strictObject({
  id: Id,
  email: z.email(),
  displayName: z.string(),
  roles: z.array(RoleKeySchema),
  permissions: z.array(PermissionSchema),
  /** null = all sites; otherwise the site keys this session may see (enforced server-side). */
  sites: z.array(z.string().max(32)).nullable(),
});
export type SessionUser = z.infer<typeof SessionUser>;

export const TokenResponse = z.strictObject({
  accessToken: z.string(),
  tokenType: z.literal('Bearer'),
  expiresInSeconds: z.number().int().positive(),
  user: SessionUser,
});
export type TokenResponse = z.infer<typeof TokenResponse>;

export const CreateUserRequest = z.strictObject({
  email: z.email().max(254),
  displayName: z.string().trim().min(1).max(128),
  password: Password,
  roles: z.array(RoleKeySchema).max(9),
});
export type CreateUserRequest = z.infer<typeof CreateUserRequest>;

export const UserListResponse = z.strictObject({
  items: z.array(User),
  nextCursor: z.string().nullable(),
});

/** Capability state for the platform status endpoint — states are explicit, never implied. */
export const CapabilityState = z.enum([
  'not_implemented',
  'not_configured',
  'disabled',
  'available',
  'degraded',
]);
export type CapabilityState = z.infer<typeof CapabilityState>;

export const CapabilityStatus = z.strictObject({
  id: z.string(),
  state: CapabilityState,
  phase: z.number().int().min(0).max(7),
  reason: z.string(),
});
export type CapabilityStatus = z.infer<typeof CapabilityStatus>;

/** A metric always names its data source and says whether that source is configured. */
export const MetricValue = z.strictObject({
  id: z.string(),
  source: z.string(),
  sourceState: z.enum(['available', 'not_configured', 'unreachable']),
  value: z.number().nullable(),
  observedAt: Timestamp.nullable(),
});

export const PlatformStatus = z.strictObject({
  service: z.literal('noc-api'),
  version: z.string(),
  environment: z.enum(['development', 'test', 'production']),
  demoData: z.literal(false),
  database: z.strictObject({
    state: z.enum(['available', 'unreachable']),
    migrationsApplied: z.number().int().nonnegative(),
  }),
  capabilities: z.array(CapabilityStatus),
  metrics: z.array(MetricValue),
  assuranceStates: z.array(z.enum(AssuranceStateValues)),
  generatedAt: Timestamp,
});
export type PlatformStatus = z.infer<typeof PlatformStatus>;

export const AuditVerifyResponse = z.strictObject({
  valid: z.boolean(),
  eventsChecked: z.number().int().nonnegative(),
  firstBrokenSeq: z.number().int().nullable(),
  reason: z.string().nullable(),
});
export type AuditVerifyResponse = z.infer<typeof AuditVerifyResponse>;

// ---- Phase 1: asset inventory & network ----------------------------------------------------

/** What a collector submits. Ids and links are assigned by the platform, never by the collector. */
export const IngestObservationRequest = AssetObservation.omit({
  id: true,
  assetId: true,
  conflictsWith: true,
});
export type IngestObservationRequest = z.infer<typeof IngestObservationRequest>;

export const IngestObservationResponse = z.strictObject({
  observationId: Id,
  assetId: Id.nullable(),
  decision: z.enum(['match', 'create', 'ambiguous']),
  reason: z.string().max(64),
  confidence: z.number().min(0).max(1).nullable(),
  conflicts: z.array(z.string().max(64)).max(16),
  candidateIds: z.array(Id).max(50),
});
export type IngestObservationResponse = z.infer<typeof IngestObservationResponse>;

export const AssetListQuery = PageQuery.extend({
  segmentId: Id.optional(),
  assetClass: AssetClass.optional(),
  coverage: CoverageState.optional(),
  status: OperationalStatus.optional(),
  q: z.string().trim().min(1).max(128).optional(),
});
export type AssetListQuery = z.infer<typeof AssetListQuery>;

export const AssetDetail = z.strictObject({
  asset: Asset,
  interfaces: z.array(AssetInterface),
  services: z.array(AssetServiceRecord),
});
export type AssetDetail = z.infer<typeof AssetDetail>;

/** Operator-maintained metadata only. Identity fields (hostname, addresses) come from observations. */
export const AssetPatchRequest = z
  .strictObject({
    assetClass: AssetClass.optional(),
    criticality: Criticality.optional(),
    role: ShortText.nullable().optional(),
    owner: ShortText.nullable().optional(),
    responsibleTeam: ShortText.nullable().optional(),
    segmentId: Id.nullable().optional(),
  })
  .refine((o) => Object.keys(o).length > 0, 'Patch must change at least one field');
export type AssetPatchRequest = z.infer<typeof AssetPatchRequest>;

export const AssetCoverageSummary = z.strictObject({
  total: z.number().int().nonnegative(),
  byCoverage: z.record(CoverageState, z.number().int().nonnegative()),
  byAssurance: z.record(AssuranceState, z.number().int().nonnegative()),
  byClass: z.record(z.string(), z.number().int().nonnegative()),
  unresolvedObservations: z.number().int().nonnegative(),
  generatedAt: Timestamp,
});
export type AssetCoverageSummary = z.infer<typeof AssetCoverageSummary>;

export const AssetTimelineEntry = z.strictObject({
  at: Timestamp,
  kind: z.enum(['observation', 'audit']),
  summary: z.string().max(512),
  ref: z.string().max(128),
});
export type AssetTimelineEntry = z.infer<typeof AssetTimelineEntry>;

export const CreateSegmentRequest = NetworkSegment.omit({ id: true });
export type CreateSegmentRequest = z.infer<typeof CreateSegmentRequest>;

export const TopologyGraph = z.strictObject({
  nodes: z.array(
    z.strictObject({
      id: Id,
      label: z.string().max(256),
      assetClass: AssetClass,
      segmentId: Id.nullable(),
      operationalStatus: OperationalStatus,
    }),
  ),
  edges: z.array(TopologyRelationship),
  truncated: z.boolean(),
  generatedAt: Timestamp,
});
export type TopologyGraph = z.infer<typeof TopologyGraph>;
