import { z } from 'zod';
import { Id, Sha256, ShortText, Timestamp } from '../common';

export const DetectionValidationStatusValues = [
  'queued',
  'dispatched',
  'completed',
  'failed',
  'expired',
] as const;
export const DetectionValidationStatus = z.enum(DetectionValidationStatusValues);
export type DetectionValidationStatus = z.infer<typeof DetectionValidationStatus>;

export const ValidationVerdictValues = ['passed', 'failed', 'inconclusive'] as const;
export const ValidationVerdict = z.enum(ValidationVerdictValues);
export type ValidationVerdict = z.infer<typeof ValidationVerdict>;

/** A file name inside the sensor's sample directory — never a path. */
export const SampleRef = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);

export const CreateDetectionValidationRequest = z.strictObject({
  ruleId: Id,
  sensorId: Id,
  sampleRef: SampleRef,
  note: z.string().trim().max(1024).nullable().default(null),
});
export type CreateDetectionValidationRequest = z.infer<typeof CreateDetectionValidationRequest>;

export const DetectionValidation = z.strictObject({
  id: Id,
  ruleId: Id,
  ruleName: ShortText,
  ruleExternalId: z.string().max(64),
  sensorId: Id,
  sensorName: ShortText,
  sampleRef: SampleRef,
  status: DetectionValidationStatus,
  /** Bundle the sensor must be running for the result to count. */
  expectedBundleSha256: Sha256.nullable(),
  reportedBundleSha256: Sha256.nullable(),
  expectedSids: z.array(z.number().int().positive()).max(64),
  firedSids: z.array(z.number().int().positive()).max(10_000),
  missingSids: z.array(z.number().int().positive()).max(64),
  /** Signatures that fired but were not expected (informational; a sample may trip several). */
  unexpectedCount: z.number().int().nonnegative(),
  verdict: ValidationVerdict.nullable(),
  engineVersion: z.string().max(64).nullable(),
  error: z.string().max(512).nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  note: z.string().max(1024).nullable(),
  requestedBy: Id,
  createdAt: Timestamp,
  dispatchedAt: Timestamp.nullable(),
  reportedAt: Timestamp.nullable(),
  expiresAt: Timestamp,
});
export type DetectionValidation = z.infer<typeof DetectionValidation>;

export const ValidationListQuery = z.strictObject({
  ruleId: Id.optional(),
  sensorId: Id.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/** What a sensor fetches: run `sampleRef` offline against the bundle it is running and report. */
export const SensorValidationDirective = z.strictObject({
  id: Id,
  sampleRef: SampleRef,
  expectedBundleSha256: Sha256.nullable(),
  expectedSids: z.array(z.number().int().positive()).max(64),
  expiresAt: Timestamp,
});
export type SensorValidationDirective = z.infer<typeof SensorValidationDirective>;

export const ValidationResultRequest = z.strictObject({
  firedSids: z.array(z.number().int().positive()).max(10_000),
  rulesBundleSha256: Sha256.nullable(),
  engineVersion: z.string().max(64).nullable(),
  /** Set when the sensor could not run the sample (missing file, engine error); no verdict then. */
  error: z.string().max(512).nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
});
export type ValidationResultRequest = z.infer<typeof ValidationResultRequest>;

/** Re-prove a rule on a sensor every N days; the scheduler queues a validation when the last pass is older. */
export const ValidationSchedule = z.strictObject({
  id: Id,
  ruleId: Id,
  ruleName: ShortText,
  ruleExternalId: z.string().max(64),
  sensorId: Id,
  sensorName: ShortText,
  sampleRef: SampleRef,
  intervalDays: z.number().int().min(1).max(30),
  enabled: z.boolean(),
  note: z.string().max(1024).nullable(),
  createdBy: Id,
  createdAt: Timestamp,
  lastQueuedAt: Timestamp.nullable(),
  /** Why the scheduler could not queue last time (rule no longer deployed, sensor disabled…). */
  lastError: z.string().max(512).nullable(),
  /** Most recent completed verdict for this rule/sensor pair, with its time; null when none. */
  lastVerdict: ValidationVerdict.nullable(),
  lastVerdictAt: Timestamp.nullable(),
});
export type ValidationSchedule = z.infer<typeof ValidationSchedule>;

export const CreateValidationScheduleRequest = z.strictObject({
  ruleId: Id,
  sensorId: Id,
  sampleRef: SampleRef,
  intervalDays: z.number().int().min(1).max(30).default(7),
  note: z.string().trim().max(1024).nullable().default(null),
});
export type CreateValidationScheduleRequest = z.infer<typeof CreateValidationScheduleRequest>;

export const UpdateValidationScheduleRequest = z.strictObject({
  enabled: z.boolean().optional(),
  intervalDays: z.number().int().min(1).max(30).optional(),
});
