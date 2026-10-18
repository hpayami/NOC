import { z } from 'zod';
import { Id, LongText, Timestamp } from '../common';
import { ApprovalDecision, ResponseActionKind, ResponseActionStatus } from '../enums';
import { ResponseAction } from './governance';

export const RESPONSE_TARGET_TYPES = [
  'asset',
  'ip',
  'user',
  'session',
  'rule',
  'indicator',
  'incident',
] as const;
export const ResponseTargetType = z.enum(RESPONSE_TARGET_TYPES);
export type ResponseTargetType = z.infer<typeof ResponseTargetType>;

/**
 * A proposal never changes anything. Justification and a rollback plan are mandatory so the
 * approver can judge impact and the executor can undo it.
 */
export const ProposeResponseActionRequest = z.strictObject({
  kind: ResponseActionKind,
  incidentId: Id.nullable().default(null),
  targetType: ResponseTargetType,
  targetRef: z.string().trim().min(1).max(512),
  justification: z.string().trim().min(10).max(4096),
  rollbackPlan: z.string().trim().min(10).max(8192),
  triggeringEvidence: z.array(z.string().max(512)).max(32).default([]),
  parameters: z
    .record(z.string(), z.unknown())
    .default({})
    .refine((v) => JSON.stringify(v).length <= 8192, { message: 'parameters exceed 8 KiB' }),
  expiresInHours: z.number().int().min(1).max(168).default(24),
});
export type ProposeResponseActionRequest = z.infer<typeof ProposeResponseActionRequest>;

export const ResponseDecisionRequest = z.strictObject({
  justification: z.string().trim().min(5).max(4096),
});
export type ResponseDecisionRequest = z.infer<typeof ResponseDecisionRequest>;

export const ResponseExecutionRequest = z.strictObject({
  note: z.string().trim().max(4096).optional(),
});
export type ResponseExecutionRequest = z.infer<typeof ResponseExecutionRequest>;

export const ResponseApprovalRecord = z.strictObject({
  approverId: Id,
  decision: ApprovalDecision,
  justification: LongText,
  decidedAt: Timestamp,
});
export type ResponseApprovalRecord = z.infer<typeof ResponseApprovalRecord>;

export const ResponseActionRecord = ResponseAction.extend({
  justification: LongText,
  parameters: z.record(z.string(), z.unknown()),
  requiredApprovals: z.number().int().nonnegative(),
  approvals: z.array(ResponseApprovalRecord),
  approvalsGranted: z.number().int().nonnegative(),
  executedBy: Id.nullable(),
  result: z.record(z.string(), z.unknown()),
  /** Whether this platform build can execute the kind at all; false means approval is possible but execution is refused. */
  executorAvailable: z.boolean(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type ResponseActionRecord = z.infer<typeof ResponseActionRecord>;

export const ResponseActionListQuery = z.strictObject({
  incidentId: Id.optional(),
  status: ResponseActionStatus.optional(),
  kind: ResponseActionKind.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(512).optional(),
});
export type ResponseActionListQuery = z.infer<typeof ResponseActionListQuery>;

export const ResponseExecutorInfo = z.strictObject({
  kind: ResponseActionKind,
  available: z.boolean(),
  requiredApprovals: z.number().int().nonnegative(),
  description: z.string().max(512),
});
export type ResponseExecutorInfo = z.infer<typeof ResponseExecutorInfo>;
