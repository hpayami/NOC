import { z } from 'zod';
import { Id, ShortText, Timestamp } from '../common';
import { UserStatus } from '../enums';
import { PermissionSchema, RoleKeySchema } from '../rbac';

/** Public user representation. Never includes password hashes, MFA secrets or token material. */
export const User = z.strictObject({
  id: Id,
  email: z.email().max(254),
  displayName: ShortText,
  status: UserStatus,
  roles: z.array(RoleKeySchema),
  mfaEnrolled: z.boolean(),
  /** 'local' password accounts or 'oidc' single sign-on; SSO accounts cannot log in with a password. */
  authProvider: z.enum(['local', 'oidc']),
  allSites: z.boolean(),
  sites: z.array(z.string().max(32)),
  lastLoginAt: Timestamp.nullable(),
  createdAt: Timestamp,
});
export type User = z.infer<typeof User>;

export const Role = z.strictObject({
  key: RoleKeySchema,
  name: ShortText,
  nameFa: ShortText,
  description: z.string().max(512),
  permissions: z.array(PermissionSchema),
});
export type Role = z.infer<typeof Role>;

export const PermissionInfo = z.strictObject({
  key: PermissionSchema,
  description: z.string().max(256),
});
export type PermissionInfo = z.infer<typeof PermissionInfo>;

export const Approval = z.strictObject({
  id: Id,
  subjectType: z.enum([
    'response_action',
    'assessment_engagement',
    'detection_rule_deployment',
    'ips_policy',
  ]),
  subjectId: Id,
  approverId: Id,
  decision: z.enum(['approved', 'rejected']),
  justification: z.string().max(2048),
  decidedAt: Timestamp,
});
export type Approval = z.infer<typeof Approval>;

export const AuditEvent = z.strictObject({
  id: Id,
  seq: z.number().int().nonnegative(),
  occurredAt: Timestamp,
  actorId: Id.nullable(),
  actorLabel: z.string().max(256),
  action: z.string().max(128),
  outcome: z.enum(['success', 'denied', 'failure']),
  targetType: z.string().max(64).nullable(),
  targetId: z.string().max(128).nullable(),
  requestId: z.string().max(64).nullable(),
  sourceIp: z.string().max(64).nullable(),
  metadata: z.record(z.string(), z.unknown()),
  prevHash: z.string().length(64),
  hash: z.string().length(64),
});
export type AuditEvent = z.infer<typeof AuditEvent>;
