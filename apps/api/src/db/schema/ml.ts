import { index, jsonb, pgEnum, pgTable, real, text, timestamp, uuid } from 'drizzle-orm/pg-core';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const mlSubjectTypeEnum = pgEnum('ml_subject_type', ['asset', 'flow', 'alert', 'dns_query']);

/**
 * Advisory inference results. Nothing reads this table to take an action; it exists so a human can
 * see what the model said, with the inputs and the explanation, and so results can be audited.
 */
export const mlInferenceResults = pgTable(
  'ml_inference_results',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    modelName: text('model_name').notNull(),
    modelVersion: text('model_version').notNull(),
    featureSetVersion: text('feature_set_version').notNull(),
    subjectType: mlSubjectTypeEnum('subject_type').notNull(),
    subjectId: text('subject_id').notNull(),
    score: real('score').notNull(),
    explanation: jsonb('explanation')
      .$type<Array<{ feature: string; contribution: number }>>()
      .notNull()
      .default([]),
    features: jsonb('features')
      .$type<Array<{ feature: string; current: number; median: number; mad: number; z: number }>>()
      .notNull()
      .default([]),
    evidenceRefs: jsonb('evidence_refs').$type<unknown[]>().notNull().default([]),
    windowStart: ts('window_start').notNull(),
    windowEnd: ts('window_end').notNull(),
    requestedBy: uuid('requested_by'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    index('ml_results_subject_created_idx').on(t.subjectType, t.subjectId, t.createdAt),
    index('ml_results_created_idx').on(t.createdAt),
    index('ml_results_score_idx').on(t.score),
  ],
);
