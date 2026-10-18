import {
  boolean,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { severityEnum } from './enums';
import { alerts, securityEvents } from './secops';
import { assets } from './assets';
import { sensors } from './sensors';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

/** Indicators of compromise the operator imported; identity is (type, canonical value). */
export const threatIndicators = pgTable(
  'threat_indicators',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    type: text('type').notNull(),
    value: text('value').notNull(),
    source: text('source').notNull(),
    confidence: integer('confidence').notNull().default(50),
    severity: severityEnum('severity').notNull().default('medium'),
    tags: text('tags').array().notNull().default([]),
    description: text('description'),
    expiresAt: ts('expires_at'),
    revoked: boolean('revoked').notNull().default(false),
    importedAt: ts('imported_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
    matchCount: integer('match_count').notNull().default(0),
    lastMatchedAt: ts('last_matched_at'),
  },
  (t) => [
    uniqueIndex('threat_indicators_type_value_idx').on(t.type, t.value),
    index('threat_indicators_source_idx').on(t.source),
    index('threat_indicators_active_idx').on(t.revoked, t.expiresAt),
  ],
);

/** One indicator seen in one event field; the alert it raised or bumped is linked. */
export const threatIndicatorMatches = pgTable(
  'threat_indicator_matches',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    indicatorId: uuid('indicator_id')
      .notNull()
      .references(() => threatIndicators.id, { onDelete: 'cascade' }),
    eventId: uuid('event_id')
      .notNull()
      .references(() => securityEvents.id, { onDelete: 'cascade' }),
    alertId: uuid('alert_id').references(() => alerts.id, { onDelete: 'set null' }),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    sensorId: uuid('sensor_id').references(() => sensors.id, { onDelete: 'set null' }),
    matchedField: text('matched_field').notNull(),
    matchedValue: text('matched_value').notNull(),
    observedAt: ts('observed_at').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('threat_indicator_matches_unique_idx').on(t.indicatorId, t.eventId, t.matchedField),
    index('threat_indicator_matches_observed_idx').on(t.observedAt),
    index('threat_indicator_matches_asset_idx').on(t.assetId),
  ],
);
