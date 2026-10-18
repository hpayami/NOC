import { z } from 'zod';
import { Id, IpAddress, Timestamp } from '../common';
import { AlertStatus, EventCategory, Severity } from '../enums';
import { ALERT_ACTIONS } from '../rules/alert-state';
import { Alert, NormalizedEvent } from './secops';

export const INGEST_MAX_RECORDS = 1000;

export const IngestReport = z.strictObject({
  received: z.number().int().nonnegative(),
  accepted: z.number().int().nonnegative(),
  duplicates: z.number().int().nonnegative(),
  rejected: z.number().int().nonnegative(),
  /** First rejections, so a misconfigured sensor can be fixed; nothing is dropped silently. */
  rejections: z
    .array(z.strictObject({ index: z.number().int().nonnegative(), reason: z.string().max(256) }))
    .max(20),
  alertsCreated: z.number().int().nonnegative(),
  alertsUpdated: z.number().int().nonnegative(),
  maxEventLagSeconds: z.number().nullable(),
});
export type IngestReport = z.infer<typeof IngestReport>;

export const EventsQuery = z.strictObject({
  from: Timestamp,
  to: Timestamp,
  sensorId: Id.optional(),
  category: EventCategory.optional(),
  type: z.string().max(64).optional(),
  severity: Severity.optional(),
  ip: IpAddress.optional(),
  assetId: Id.optional(),
  ruleId: z.string().max(128).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  cursor: z.string().max(512).optional(),
});
export type EventsQuery = z.infer<typeof EventsQuery>;

export const EventStats = z.strictObject({
  windowHours: z.number().int(),
  byType: z.record(z.string(), z.number().int().nonnegative()),
  bySeverity: z.record(Severity, z.number().int().nonnegative()),
  total: z.number().int().nonnegative(),
  sensors: z.array(
    z.strictObject({
      sensorId: Id,
      name: z.string(),
      kind: z.string(),
      lastEventAt: Timestamp.nullable(),
      lagSeconds: z.number().nullable(),
      events: z.number().int().nonnegative(),
    }),
  ),
  generatedAt: Timestamp,
});
export type EventStats = z.infer<typeof EventStats>;

export const AlertListQuery = z.strictObject({
  status: AlertStatus.optional(),
  open: z.coerce.boolean().optional(),
  severity: Severity.optional(),
  assetId: Id.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(512).optional(),
});
export type AlertListQuery = z.infer<typeof AlertListQuery>;

export const AlertTriageRequest = z
  .strictObject({
    action: z.enum(ALERT_ACTIONS),
    note: z.string().trim().max(2048).optional(),
    suppressedUntil: Timestamp.optional(),
    assigneeId: Id.nullable().optional(),
  })
  .refine((r) => r.action !== 'suppress' || !!r.suppressedUntil, {
    message: 'suppress requires suppressedUntil',
  });
export type AlertTriageRequest = z.infer<typeof AlertTriageRequest>;

export const AlertDetail = z.strictObject({
  alert: Alert.extend({
    ruleRef: z.string().max(128).nullable(),
    srcIp: IpAddress.nullable(),
    dstIp: IpAddress.nullable(),
    sourceSensorId: Id.nullable(),
  }),
  recentEvents: z.array(NormalizedEvent),
});
export type AlertDetail = z.infer<typeof AlertDetail>;
