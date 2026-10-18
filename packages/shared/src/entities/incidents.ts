import { z } from 'zod';
import { Id, LongText, ShortText, Timestamp } from '../common';
import { IncidentStatus, IncidentType, Severity } from '../enums';
import { Alert, Incident } from './secops';

/** Append-only timeline entry kinds. Everything that changes an incident leaves one. */
export const INCIDENT_TIMELINE_KINDS = [
  'opened',
  'transition',
  'note',
  'assignment',
  'severity_changed',
  'updated',
  'alert_linked',
  'alert_unlinked',
  'response_action',
] as const;
export const IncidentTimelineKind = z.enum(INCIDENT_TIMELINE_KINDS);
export type IncidentTimelineKind = z.infer<typeof IncidentTimelineKind>;

export const IncidentTimelineEntry = z.strictObject({
  id: Id,
  occurredAt: Timestamp,
  actorId: Id.nullable(),
  kind: IncidentTimelineKind,
  fromStatus: IncidentStatus.nullable(),
  toStatus: IncidentStatus.nullable(),
  note: LongText.nullable(),
  payload: z.record(z.string(), z.unknown()),
});
export type IncidentTimelineEntry = z.infer<typeof IncidentTimelineEntry>;

export const IncidentSummary = Incident.extend({
  openedBy: Id.nullable(),
  updatedAt: Timestamp,
  alertCount: z.number().int().nonnegative(),
});
export type IncidentSummary = z.infer<typeof IncidentSummary>;

export const IncidentDetail = z.strictObject({
  incident: IncidentSummary.extend({
    /** States reachable from the current one per the lifecycle rules (permission not applied). */
    allowedNext: z.array(IncidentStatus),
  }),
  alerts: z.array(Alert),
  timeline: z.array(IncidentTimelineEntry),
});
export type IncidentDetail = z.infer<typeof IncidentDetail>;

export const CreateIncidentRequest = z.strictObject({
  title: ShortText,
  type: IncidentType.default('security'),
  severity: Severity,
  summary: LongText.default(''),
  /** Alerts to attach at creation; open ones are escalated. */
  alertIds: z.array(Id).max(50).default([]),
});
export type CreateIncidentRequest = z.infer<typeof CreateIncidentRequest>;

export const IncidentTransitionRequest = z.strictObject({
  to: IncidentStatus,
  reason: z.string().trim().max(2048).optional(),
});
export type IncidentTransitionRequest = z.infer<typeof IncidentTransitionRequest>;

export const IncidentNoteRequest = z.strictObject({
  note: z.string().trim().min(1).max(8192),
});
export type IncidentNoteRequest = z.infer<typeof IncidentNoteRequest>;

export const IncidentUpdateRequest = z
  .strictObject({
    title: ShortText.optional(),
    summary: LongText.optional(),
    severity: Severity.optional(),
    assigneeId: Id.nullable().optional(),
    commanderId: Id.nullable().optional(),
  })
  .refine((o) => Object.values(o).some((v) => v !== undefined), {
    message: 'At least one field must be provided',
  });
export type IncidentUpdateRequest = z.infer<typeof IncidentUpdateRequest>;

export const IncidentLinkAlertsRequest = z.strictObject({
  alertIds: z.array(Id).min(1).max(50),
});
export type IncidentLinkAlertsRequest = z.infer<typeof IncidentLinkAlertsRequest>;

export const IncidentListQuery = z.strictObject({
  status: IncidentStatus.optional(),
  open: z.coerce.boolean().optional(),
  severity: Severity.optional(),
  type: IncidentType.optional(),
  assigneeId: Id.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(512).optional(),
});
export type IncidentListQuery = z.infer<typeof IncidentListQuery>;

export const IncidentStats = z.strictObject({
  total: z.number().int().nonnegative(),
  open: z.number().int().nonnegative(),
  byStatus: z.record(IncidentStatus, z.number().int().nonnegative()),
  bySeverity: z.record(Severity, z.number().int().nonnegative()),
  closedLast30Days: z.number().int().nonnegative(),
  /** Mean open→close duration over incidents closed in the last 30 days; null when none closed. */
  meanTimeToCloseSeconds: z.number().nonnegative().nullable(),
  generatedAt: Timestamp,
});
export type IncidentStats = z.infer<typeof IncidentStats>;
