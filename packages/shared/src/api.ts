import { z } from 'zod';
import { Id, Timestamp } from './common';
import { AssuranceStateValues } from './enums';
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
