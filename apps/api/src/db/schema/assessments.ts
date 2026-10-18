import {
  boolean,
  index,
  inet,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import { AssessmentTechniqueValues, RunStatusValues } from '@noc/shared';
import { assessmentEngagements } from './governance';
import { users } from './identity';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const assessmentTechniqueEnum = pgEnum('assessment_technique', AssessmentTechniqueValues);
export const assessmentRunStatusEnum = pgEnum('assessment_run_status', RunStatusValues);

/**
 * One execution of one technique against the engagement's approved scope version. Targets are
 * enumerated at creation; the scope decision for each is re-evaluated by the worker right before
 * any connection attempt.
 */
export const assessmentRuns = pgTable(
  'assessment_runs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => assessmentEngagements.id, { onDelete: 'cascade' }),
    scopeVersion: integer('scope_version').notNull(),
    technique: assessmentTechniqueEnum('technique').notNull(),
    status: assessmentRunStatusEnum('status').notNull().default('queued'),
    dryRun: boolean('dry_run').notNull().default(true),
    ports: integer('ports').array().notNull().default([]),
    requestedBy: uuid('requested_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    note: text('note'),
    targetCount: integer('target_count').notNull().default(0),
    startedAt: ts('started_at'),
    finishedAt: ts('finished_at'),
    summary: jsonb('summary').$type<Record<string, number> | null>(),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [index('assessment_runs_engagement_created_idx').on(t.engagementId, t.createdAt)],
);

export const assessmentRunTargets = pgTable(
  'assessment_run_targets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    runId: uuid('run_id')
      .notNull()
      .references(() => assessmentRuns.id, { onDelete: 'cascade' }),
    target: inet('target').notNull(),
    decision: text('decision').notNull().default('pending'),
    reasons: text('reasons').array().notNull().default([]),
    outcome: text('outcome').notNull().default('pending'),
    openPorts: integer('open_ports').array().notNull().default([]),
    observedAt: ts('observed_at'),
  },
  (t) => [index('assessment_run_targets_run_idx').on(t.runId)],
);
