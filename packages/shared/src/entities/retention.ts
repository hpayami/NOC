import { z } from 'zod';
import { Timestamp } from '../common';
import { RetentionDataClass } from './governance';

/** The audit trail can never be retained for less than this many days. */
export const AUDIT_RETENTION_FLOOR_DAYS = 365;

export const RetentionPolicyUpdate = z.strictObject({
  retentionDays: z.number().int().min(1).max(3650),
  legalHold: z.boolean().default(false),
});
export type RetentionPolicyUpdate = z.infer<typeof RetentionPolicyUpdate>;

export const RetentionDatasetOutcome = z.enum([
  /** Rows older than the cutoff were deleted. */
  'purged',
  /** More rows remain past the cutoff; the run was bounded and will continue next time. */
  'truncated',
  /** Policy has a legal hold: nothing deleted. */
  'legal_hold',
  /** Dataset is never purged automatically (audit trail). */
  'protected',
  /** No store exists for this class yet (nothing to purge, honestly reported). */
  'dataset_absent',
  'failed',
]);
export type RetentionDatasetOutcome = z.infer<typeof RetentionDatasetOutcome>;

export const RetentionDatasetReport = z.strictObject({
  dataClass: RetentionDataClass,
  dataset: z.string().max(64),
  retentionDays: z.number().int().positive(),
  cutoff: Timestamp,
  deleted: z.number().int().nonnegative(),
  outcome: RetentionDatasetOutcome,
  detail: z.string().max(512).nullable(),
});
export type RetentionDatasetReport = z.infer<typeof RetentionDatasetReport>;

export const RetentionRunReport = z.strictObject({
  startedAt: Timestamp,
  finishedAt: Timestamp,
  trigger: z.enum(['scheduled', 'manual']),
  datasets: z.array(RetentionDatasetReport),
  totalDeleted: z.number().int().nonnegative(),
});
export type RetentionRunReport = z.infer<typeof RetentionRunReport>;
