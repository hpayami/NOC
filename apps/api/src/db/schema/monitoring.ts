import {
  bigserial,
  boolean,
  doublePrecision,
  index,
  inet,
  integer,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets, networkSegments } from './assets';
import { checkKindEnum, checkOutcomeEnum } from './enums';
import { sensors } from './sensors';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const monitoringChecks = pgTable(
  'monitoring_checks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    kind: checkKindEnum('kind').notNull(),
    /** Must be one of the asset's known addresses; public addresses are refused at creation. */
    target: inet('target').notNull(),
    port: integer('port'),
    intervalSeconds: integer('interval_seconds').notNull().default(60),
    timeoutMs: integer('timeout_ms').notNull().default(2000),
    enabled: boolean('enabled').notNull().default(true),
    collectorId: uuid('collector_id').references(() => sensors.id, { onDelete: 'set null' }),
    lastRunAt: ts('last_run_at'),
    createdBy: uuid('created_by'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    index('monitoring_checks_due_idx').on(t.enabled, t.collectorId, t.lastRunAt),
    index('monitoring_checks_asset_idx').on(t.assetId),
  ],
);

/** Time series of check outcomes. Subject to the `metrics` retention class. */
export const checkResults = pgTable(
  'check_results',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    checkId: uuid('check_id')
      .notNull()
      .references(() => monitoringChecks.id, { onDelete: 'cascade' }),
    observedAt: ts('observed_at').notNull(),
    outcome: checkOutcomeEnum('outcome').notNull(),
    latencyMs: integer('latency_ms'),
    detail: text('detail'),
    collectorState: text('collector_state').notNull().default('platform'),
  },
  (t) => [index('check_results_check_time_idx').on(t.checkId, t.observedAt)],
);

export const maintenanceWindows = pgTable(
  'maintenance_windows',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'cascade' }),
    segmentId: uuid('segment_id').references(() => networkSegments.id, { onDelete: 'cascade' }),
    startsAt: ts('starts_at').notNull(),
    endsAt: ts('ends_at').notNull(),
    reason: text('reason').notNull().default(''),
    createdBy: uuid('created_by'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    index('maintenance_windows_range_idx').on(t.startsAt, t.endsAt),
    index('maintenance_windows_asset_idx').on(t.assetId),
    index('maintenance_windows_segment_idx').on(t.segmentId),
  ],
);

/** Low-cardinality numeric telemetry per asset (CPU, memory, interface counters…). */
export const assetMetrics = pgTable(
  'asset_metrics',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    metric: text('metric').notNull(),
    observedAt: ts('observed_at').notNull(),
    value: doublePrecision('value').notNull(),
    unit: text('unit'),
    source: text('source').notNull(),
  },
  (t) => [index('asset_metrics_asset_metric_time_idx').on(t.assetId, t.metric, t.observedAt)],
);
