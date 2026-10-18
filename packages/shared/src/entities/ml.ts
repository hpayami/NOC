import { z } from 'zod';
import { Id, Timestamp } from '../common';
import { MlInferenceResult } from './secops';

export const ML_FEATURE_SET_VERSION = 'asset-hourly-v1' as const;
/** Hourly buckets of history used as the per-subject baseline. */
export const ML_HISTORY_HOURS = 168;

export const MlModelStatus = z.strictObject({
  name: z.string().max(64),
  version: z.string().max(64),
  state: z.enum(['not_trained', 'advisory', 'disabled']),
  kind: z.enum(['statistical_baseline', 'learned']),
  evaluation: z.string().max(512),
  minHistoryPoints: z.number().int().nonnegative(),
});

/** What the API knows about the analysis service right now; `reachable: false` is a real state. */
export const MlStatus = z.strictObject({
  analysisUrl: z.string().max(256),
  reachable: z.boolean(),
  checkedAt: Timestamp,
  detail: z.string().max(512).nullable(),
  advisoryOnly: z.literal(true),
  externalModelApisAllowed: z.boolean().nullable(),
  models: z.array(MlModelStatus),
  resultCount: z.number().int().nonnegative(),
});
export type MlStatus = z.infer<typeof MlStatus>;

export const MlScoreRequest = z.strictObject({
  subjectType: z.literal('asset'),
  subjectId: Id,
});
export type MlScoreRequest = z.infer<typeof MlScoreRequest>;

export const MlBatchScoreRequest = z.strictObject({
  /** Score every asset that produced events in the history window; bounded. */
  limit: z.number().int().min(1).max(200).default(50),
});

export const MlFeatureSnapshot = z.strictObject({
  feature: z.string().max(64),
  current: z.number(),
  median: z.number(),
  mad: z.number(),
  z: z.number(),
});

export const MlScoreRecord = MlInferenceResult.extend({
  features: z.array(MlFeatureSnapshot),
  windowStart: Timestamp,
  windowEnd: Timestamp,
});
export type MlScoreRecord = z.infer<typeof MlScoreRecord>;

export const MlBatchScoreResponse = z.strictObject({
  scored: z.number().int().nonnegative(),
  skipped: z.array(z.strictObject({ subjectId: Id, reason: z.string().max(256) })),
  results: z.array(MlScoreRecord),
});
export type MlBatchScoreResponse = z.infer<typeof MlBatchScoreResponse>;

export const MlResultListQuery = z.strictObject({
  subjectId: Id.optional(),
  minScore: z.coerce.number().min(0).max(1).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
