import {
  boolean,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import { discoveryJobStatusEnum } from './enums';
import { users } from './identity';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

/** Approval-gated active discovery. The scope is immutable once requested; a change is a new job. */
export const discoveryJobs = pgTable(
  'discovery_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    status: discoveryJobStatusEnum('status').notNull().default('pending_approval'),
    dryRun: boolean('dry_run').notNull().default(true),
    scope: jsonb('scope').$type<Record<string, unknown>>().notNull(),
    ports: integer('ports').array().notNull().default([]),
    requestedBy: uuid('requested_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    approvedBy: uuid('approved_by').references(() => users.id, { onDelete: 'set null' }),
    approvalNote: text('approval_note'),
    targetCount: integer('target_count').notNull().default(0),
    startedAt: ts('started_at'),
    finishedAt: ts('finished_at'),
    summary: jsonb('summary').$type<Record<string, number> | null>(),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('discovery_jobs_status_created_idx').on(t.status, t.createdAt),
    index('discovery_jobs_requester_idx').on(t.requestedBy),
  ],
);

export const discoveryJobTargets = pgTable(
  'discovery_job_targets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id')
      .notNull()
      .references(() => discoveryJobs.id, { onDelete: 'cascade' }),
    target: inet('target').notNull(),
    decision: text('decision').notNull().default('pending'),
    reasons: text('reasons').array().notNull().default([]),
    outcome: text('outcome').notNull().default('pending'),
    openPorts: integer('open_ports').array().notNull().default([]),
    observedAt: ts('observed_at'),
  },
  (t) => [index('discovery_job_targets_job_idx').on(t.jobId, t.outcome)],
);
