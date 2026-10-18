import {
  boolean,
  index,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import { users } from './identity';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const notificationChannels = pgTable('notification_channels', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  kind: text('kind').notNull().default('webhook'),
  url: text('url').notNull(),
  /** HMAC key the platform signs with; write-only through the API, never logged or returned. */
  secret: text('secret').notNull(),
  enabled: boolean('enabled').notNull().default(true),
  minSeverity: text('min_severity').notNull().default('warning'),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: ts('created_at').notNull().defaultNow(),
  updatedAt: ts('updated_at').notNull().defaultNow(),
  lastAttemptAt: ts('last_attempt_at'),
  lastStatus: text('last_status'),
  lastError: text('last_error'),
});

/** What each channel was last told per condition, so unchanged conditions stay quiet. */
export const notificationStates = pgTable(
  'notification_states',
  {
    channelId: uuid('channel_id')
      .notNull()
      .references(() => notificationChannels.id, { onDelete: 'cascade' }),
    conditionId: text('condition_id').notNull(),
    fingerprint: text('fingerprint').notNull(),
    active: boolean('active').notNull().default(true),
    lastSentAt: ts('last_sent_at'),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.channelId, t.conditionId] })],
);

export const notificationDeliveries = pgTable(
  'notification_deliveries',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    channelId: uuid('channel_id')
      .notNull()
      .references(() => notificationChannels.id, { onDelete: 'cascade' }),
    conditionId: text('condition_id').notNull(),
    event: text('event').notNull(),
    severity: text('severity').notNull(),
    status: text('status').notNull(),
    httpStatus: integer('http_status'),
    error: text('error'),
    attemptedAt: ts('attempted_at').notNull().defaultNow(),
  },
  (t) => [index('notification_deliveries_channel_time_idx').on(t.channelId, t.attemptedAt)],
);
