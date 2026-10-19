import { z } from 'zod';
import { Id, ShortText, Timestamp } from '../common';

export const ConditionSeverityValues = ['info', 'warning', 'critical'] as const;
export const ConditionSeverity = z.enum(ConditionSeverityValues);
export type ConditionSeverity = z.infer<typeof ConditionSeverity>;
export const CONDITION_SEVERITY_RANK: Record<ConditionSeverity, number> = {
  info: 0,
  warning: 1,
  critical: 2,
};

/** One thing an operator should act on, derived from platform records — never from assumptions. */
export const PlatformCondition = z.strictObject({
  id: z.string().min(1).max(64),
  severity: ConditionSeverity,
  title: ShortText,
  detail: z.string().max(1024),
  count: z.number().int().nonnegative(),
  /** Workspace path where the operator acts on it. */
  link: z.string().max(128).nullable(),
});
export type PlatformCondition = z.infer<typeof PlatformCondition>;

/** Every check reports, so a quiet dashboard says "checked, nothing found", not "nothing checked". */
export const ConditionCheck = z.strictObject({
  id: z.string().min(1).max(64),
  status: z.enum(['ok', 'failing', 'unavailable']),
  detail: z.string().max(512),
});
export type ConditionCheck = z.infer<typeof ConditionCheck>;

export const PlatformConditions = z.strictObject({
  conditions: z.array(PlatformCondition).max(64),
  checks: z.array(ConditionCheck).max(32),
  evaluatedAt: Timestamp,
});
export type PlatformConditions = z.infer<typeof PlatformConditions>;

export const NotificationChannelKindValues = ['webhook', 'email'] as const;
export const NotificationChannelKind = z.enum(NotificationChannelKindValues);
export type NotificationChannelKind = z.infer<typeof NotificationChannelKind>;

const Hostname = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$|^(\d{1,3}\.){3}\d{1,3}$/,
  );

/** SMTP settings of an e-mail channel; the password is write-only and lives with the channel secret. */
export const EmailChannelConfig = z.strictObject({
  host: Hostname,
  port: z.number().int().min(1).max(65535).default(587),
  /** Upgrade with STARTTLS when the server offers it (refused if it does not and this is true). */
  starttls: z.boolean().default(true),
  username: z.string().max(256).nullable().default(null),
  from: z.string().email().max(256),
  recipients: z.array(z.string().email().max(256)).min(1).max(32),
});
export type EmailChannelConfig = z.infer<typeof EmailChannelConfig>;

export const NotificationChannel = z.strictObject({
  id: Id,
  name: ShortText,
  kind: NotificationChannelKind,
  /** Webhook endpoint; null for e-mail channels. */
  url: z.string().url().max(1024).nullable(),
  /** SMTP settings; null for webhook channels. */
  email: EmailChannelConfig.nullable(),
  enabled: z.boolean(),
  minSeverity: ConditionSeverity,
  createdAt: Timestamp,
  lastAttemptAt: Timestamp.nullable(),
  lastStatus: z.enum(['sent', 'failed']).nullable(),
  lastError: z.string().max(512).nullable(),
});
export type NotificationChannel = z.infer<typeof NotificationChannel>;

const ChannelCommon = {
  name: ShortText,
  minSeverity: ConditionSeverity.default('warning'),
  enabled: z.boolean().default(true),
};

export const CreateWebhookChannelRequest = z.strictObject({
  kind: z.literal('webhook').default('webhook'),
  ...ChannelCommon,
  url: z
    .string()
    .url()
    .max(1024)
    .refine((u) => /^https?:\/\//.test(u), 'webhook URL must be http(s)'),
  /** Shared secret for the HMAC-SHA256 signature; write-only, never returned. */
  secret: z.string().min(16).max(256),
});

export const CreateEmailChannelRequest = z.strictObject({
  kind: z.literal('email'),
  ...ChannelCommon,
  email: EmailChannelConfig,
  /** SMTP password; write-only, never returned. Omit for relays that need none. */
  password: z.string().max(256).nullable().default(null),
});

export const CreateNotificationChannelRequest = z.union([
  CreateWebhookChannelRequest,
  CreateEmailChannelRequest,
]);
export type CreateNotificationChannelRequest = z.infer<typeof CreateNotificationChannelRequest>;

export const UpdateNotificationChannelRequest = z.strictObject({
  enabled: z.boolean().optional(),
  minSeverity: ConditionSeverity.optional(),
});

export const NotificationDelivery = z.strictObject({
  id: Id,
  channelId: Id,
  conditionId: z.string().max(64),
  event: z.enum(['raised', 'resolved', 'test']),
  severity: ConditionSeverity,
  status: z.enum(['sent', 'failed']),
  httpStatus: z.number().int().nullable(),
  error: z.string().max(512).nullable(),
  attemptedAt: Timestamp,
});
export type NotificationDelivery = z.infer<typeof NotificationDelivery>;

/** Body a webhook receives; signed as `sha256=<hex hmac>` in `x-noc-signature`. */
export const WebhookPayload = z.strictObject({
  event: z.enum(['raised', 'resolved', 'test']),
  condition: PlatformCondition,
  platform: z.strictObject({ service: z.literal('noc-api'), version: z.string().max(64) }),
  at: Timestamp,
});
export type WebhookPayload = z.infer<typeof WebhookPayload>;
