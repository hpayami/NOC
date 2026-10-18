import { z } from 'zod';
import { Cidr, Id, LongText, ShortText, Timestamp } from '../common';
import { ApprovalDecision } from '../enums';

/**
 * `ids`: detect only. `ips_test`: the engine logs what it *would* drop (no packet is dropped).
 * `ips`: drop/reject inside the protected ranges. Nothing in the platform defaults to `ips`.
 */
export const IpsPolicyModeValues = ['ids', 'ips_test', 'ips'] as const;
export const IpsPolicyMode = z.enum(IpsPolicyModeValues);
export type IpsPolicyMode = z.infer<typeof IpsPolicyMode>;

export const IpsPolicyStatusValues = [
  'pending_approval',
  'approved',
  'enabled',
  'disabled',
  'rejected',
  'expired',
] as const;
export const IpsPolicyStatus = z.enum(IpsPolicyStatusValues);
export type IpsPolicyStatus = z.infer<typeof IpsPolicyStatus>;

/** Why an enabled policy stopped: operator kill switch, TTL, or the sensor stopped qualifying. */
export const IpsDisableCauseValues = ['manual', 'expired', 'sensor_unhealthy'] as const;
export const IpsDisableCause = z.enum(IpsDisableCauseValues);
export type IpsDisableCause = z.infer<typeof IpsDisableCause>;

export const IpsApplyStateValues = ['none', 'pending', 'applied', 'failed'] as const;
export const IpsApplyState = z.enum(IpsApplyStateValues);
export type IpsApplyState = z.infer<typeof IpsApplyState>;

export const IpsPolicyActionValues = ['drop', 'reject'] as const;
export const IpsPolicyAction = z.enum(IpsPolicyActionValues);

/** Longest a policy may stay enabled without being re-enabled by a person. */
export const IPS_MAX_ENABLE_HOURS = 72;
/** A sensor whose last heartbeat is older than this cannot be switched inline. */
export const IPS_HEARTBEAT_MAX_AGE_SECONDS = 300;

export const ProposeIpsPolicyRequest = z.strictObject({
  name: ShortText,
  sensorId: Id,
  mode: IpsPolicyMode.exclude(['ids']),
  action: IpsPolicyAction.default('drop'),
  /** Only traffic *to* these ranges may be dropped; public ranges are refused. */
  protectedCidrs: z.array(Cidr).min(1).max(64),
  /** Never dropped, even inside protected ranges (e.g. gateways, monitoring hosts). */
  excludedCidrs: z.array(Cidr).max(64).default([]),
  /** Validated/deployed detection rules whose matches may be dropped; empty = none dropped. */
  ruleIds: z.array(Id).min(1).max(500),
  justification: z.string().trim().min(10).max(4096),
  rollbackPlan: z.string().trim().min(10).max(8192),
});
export type ProposeIpsPolicyRequest = z.infer<typeof ProposeIpsPolicyRequest>;

export const IpsDecisionRequest = z.strictObject({
  justification: z.string().trim().min(5).max(4096),
});
export const IpsEnableRequest = z.strictObject({
  enabledForHours: z.number().int().min(1).max(IPS_MAX_ENABLE_HOURS).default(24),
});
export const IpsDisableRequest = z.strictObject({
  reason: z.string().trim().min(5).max(4096),
});

export const IpsApprovalRecord = z.strictObject({
  approverId: Id,
  decision: ApprovalDecision,
  justification: LongText,
  decidedAt: Timestamp,
});

export const IpsPolicy = z.strictObject({
  id: Id,
  name: ShortText,
  sensorId: Id,
  sensorName: ShortText,
  mode: IpsPolicyMode,
  action: IpsPolicyAction,
  protectedCidrs: z.array(Cidr),
  excludedCidrs: z.array(Cidr),
  ruleIds: z.array(Id),
  status: IpsPolicyStatus,
  version: z.number().int().nonnegative(),
  justification: LongText,
  rollbackPlan: LongText,
  proposedBy: Id,
  requiredApprovals: z.number().int().nonnegative(),
  approvals: z.array(IpsApprovalRecord),
  approvalsGranted: z.number().int().nonnegative(),
  enabledBy: Id.nullable(),
  enabledAt: Timestamp.nullable(),
  expiresAt: Timestamp.nullable(),
  disabledBy: Id.nullable(),
  disabledAt: Timestamp.nullable(),
  disableReason: LongText.nullable(),
  disableCause: IpsDisableCause.nullable(),
  /** What the sensor last acknowledged; `pending` until the sensor confirms the current version. */
  applyState: IpsApplyState,
  appliedVersion: z.number().int().nonnegative().nullable(),
  appliedAt: Timestamp.nullable(),
  applyDetail: z.string().max(512).nullable(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type IpsPolicy = z.infer<typeof IpsPolicy>;

export const IpsPolicyListQuery = z.strictObject({
  sensorId: Id.optional(),
  status: IpsPolicyStatus.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/**
 * What a sensor fetches. Default (no enabled policy) is `ids` with `failOpen: true`; a sensor
 * that cannot reach the platform must keep passing traffic.
 */
export const SensorIpsDirective = z.strictObject({
  mode: IpsPolicyMode,
  policyId: Id.nullable(),
  version: z.number().int().nonnegative(),
  action: IpsPolicyAction,
  protectedCidrs: z.array(Cidr),
  excludedCidrs: z.array(Cidr),
  /** Engine rule references (`gid:sid`) — resolved from the registry at fetch time. */
  ruleRefs: z.array(z.string().max(128)),
  expiresAt: Timestamp.nullable(),
  failOpen: z.literal(true),
  issuedAt: Timestamp,
});
export type SensorIpsDirective = z.infer<typeof SensorIpsDirective>;

export const IpsAckRequest = z.strictObject({
  policyId: Id.nullable(),
  version: z.number().int().nonnegative(),
  applied: z.boolean(),
  detail: z.string().max(512).nullable().default(null),
});
export type IpsAckRequest = z.infer<typeof IpsAckRequest>;
