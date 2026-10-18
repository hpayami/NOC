import {
  bigint,
  boolean,
  index,
  integer,
  pgTable,
  real,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets';
import { sensorHealthStateEnum, sensorKindEnum, sensorModeEnum } from './enums';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const sensors = pgTable(
  'sensors',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    kind: sensorKindEnum('kind').notNull(),
    /** Inline prevention is never the default and requires an approved policy to switch on. */
    mode: sensorModeEnum('mode').notNull().default('out_of_band'),
    hostAssetId: uuid('host_asset_id').references(() => assets.id, { onDelete: 'set null' }),
    site: text('site'),
    monitoredSegmentIds: uuid('monitored_segment_ids').array().notNull().default([]),
    engineVersion: text('engine_version'),
    ruleSetVersion: text('rule_set_version'),
    enabled: boolean('enabled').notNull().default(false),
    /** SHA-256 of the sensor's long-lived credential; the credential itself is never stored. */
    credentialHash: text('credential_hash'),
    /** SHA-256 of a single-use enrolment token issued by an operator; cleared on enrolment. */
    enrolmentTokenHash: text('enrolment_token_hash'),
    enrolmentExpiresAt: ts('enrolment_expires_at'),
    enrolledAt: ts('enrolled_at'),
    registeredAt: ts('registered_at').notNull().defaultNow(),
    lastHeartbeatAt: ts('last_heartbeat_at'),
  },
  (t) => [
    index('sensors_kind_enabled_idx').on(t.kind, t.enabled),
    index('sensors_heartbeat_idx').on(t.lastHeartbeatAt),
  ],
);

export const sensorHealth = pgTable(
  'sensor_health',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    sensorId: uuid('sensor_id')
      .notNull()
      .references(() => sensors.id, { onDelete: 'cascade' }),
    recordedAt: ts('recorded_at').notNull().defaultNow(),
    state: sensorHealthStateEnum('state').notNull(),
    heartbeatAgeSeconds: integer('heartbeat_age_seconds'),
    eventLagSeconds: integer('event_lag_seconds'),
    packetsCaptured: bigint('packets_captured', { mode: 'number' }),
    packetsDropped: bigint('packets_dropped', { mode: 'number' }),
    cpuPercent: real('cpu_percent'),
    memoryPercent: real('memory_percent'),
    detail: text('detail'),
  },
  (t) => [index('sensor_health_sensor_time_idx').on(t.sensorId, t.recordedAt)],
);
