import {
  bigserial,
  char,
  index,
  inet,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { auditOutcomeEnum } from './enums';

/**
 * Tamper-evident audit trail. Rows are append-only (no UPDATE/DELETE grants in production) and each
 * row's hash covers its content plus the previous row's hash, so any edit breaks verification.
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    seq: bigserial('seq', { mode: 'number' }).primaryKey(),
    id: uuid('id').notNull().defaultRandom(),
    occurredAt: timestamp('occurred_at', { withTimezone: true, mode: 'date' }).notNull(),
    actorId: uuid('actor_id'),
    actorLabel: text('actor_label').notNull(),
    action: text('action').notNull(),
    outcome: auditOutcomeEnum('outcome').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    requestId: text('request_id'),
    sourceIp: inet('source_ip'),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().notNull().default({}),
    prevHash: char('prev_hash', { length: 64 }).notNull(),
    hash: char('hash', { length: 64 }).notNull(),
  },
  (t) => [
    uniqueIndex('audit_events_hash_idx').on(t.hash),
    uniqueIndex('audit_events_id_idx').on(t.id),
    index('audit_events_time_idx').on(t.occurredAt),
    index('audit_events_actor_time_idx').on(t.actorId, t.occurredAt),
    index('audit_events_target_idx').on(t.targetType, t.targetId),
    index('audit_events_action_idx').on(t.action),
  ],
);
