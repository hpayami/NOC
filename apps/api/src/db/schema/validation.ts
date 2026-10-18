import { index, integer, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import { detectionRules } from './secops';
import { sensors } from './sensors';
import { users } from './identity';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

/** One offline replay of a sample on a sensor against its running bundle; the verdict is derived. */
export const detectionValidations = pgTable(
  'detection_validations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ruleId: uuid('rule_id')
      .notNull()
      .references(() => detectionRules.id, { onDelete: 'cascade' }),
    sensorId: uuid('sensor_id')
      .notNull()
      .references(() => sensors.id, { onDelete: 'cascade' }),
    sampleRef: text('sample_ref').notNull(),
    status: text('status').notNull().default('queued'),
    expectedBundleSha256: text('expected_bundle_sha256'),
    reportedBundleSha256: text('reported_bundle_sha256'),
    expectedSids: integer('expected_sids').array().notNull().default([]),
    firedSids: integer('fired_sids').array().notNull().default([]),
    missingSids: integer('missing_sids').array().notNull().default([]),
    unexpectedCount: integer('unexpected_count').notNull().default(0),
    verdict: text('verdict'),
    engineVersion: text('engine_version'),
    error: text('error'),
    durationMs: integer('duration_ms'),
    note: text('note'),
    requestedBy: uuid('requested_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: ts('created_at').notNull().defaultNow(),
    dispatchedAt: ts('dispatched_at'),
    reportedAt: ts('reported_at'),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [
    index('detection_validations_sensor_status_idx').on(t.sensorId, t.status),
    index('detection_validations_rule_created_idx').on(t.ruleId, t.createdAt),
  ],
);
