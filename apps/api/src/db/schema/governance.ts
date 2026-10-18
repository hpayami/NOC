import {
  boolean,
  cidr,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  real,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  approvalDecisionEnum,
  approvalSubjectEnum,
  engagementStatusEnum,
  responseActionKindEnum,
  responseActionStatusEnum,
  retentionDataClassEnum,
} from './enums';
import { users } from './identity';
import { incidents } from './secops';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const assessmentEngagements = pgTable(
  'assessment_engagements',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    reference: text('reference').notNull(),
    authorizingOrganization: text('authorizing_organization').notNull(),
    responsibleOperatorId: uuid('responsible_operator_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    authorizationReference: text('authorization_reference').notNull(),
    status: engagementStatusEnum('status').notNull().default('draft'),
    dataHandlingRestrictions: text('data_handling_restrictions').notNull().default(''),
    stopConditions: text('stop_conditions').array().notNull().default([]),
    emergencyContact: text('emergency_contact').notNull(),
    evidenceRetentionDays: integer('evidence_retention_days').notNull().default(365),
    objective: text('objective').notNull().default(''),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    scopeVersion: integer('scope_version').notNull().default(1),
    approvedScopeVersion: integer('approved_scope_version'),
    activatedAt: ts('activated_at'),
    completedAt: ts('completed_at'),
    closeReason: text('close_reason'),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('engagements_status_idx').on(t.status),
    index('engagements_operator_idx').on(t.responsibleOperatorId),
  ],
);

/** One row per engagement; separated so scope changes are versioned independently of the engagement. */
export const assessmentScopes = pgTable(
  'assessment_scopes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => assessmentEngagements.id, { onDelete: 'cascade' }),
    version: integer('version').notNull().default(1),
    includeCidrs: cidr('include_cidrs').array().notNull().default([]),
    includeAddresses: inet('include_addresses').array().notNull().default([]),
    excludeCidrs: cidr('exclude_cidrs').array().notNull().default([]),
    excludeAddresses: inet('exclude_addresses').array().notNull().default([]),
    allowPublicAddresses: boolean('allow_public_addresses').notNull().default(false),
    allowedTechniques: text('allowed_techniques').array().notNull().default([]),
    windowStart: ts('window_start').notNull(),
    windowEnd: ts('window_end').notNull(),
    maxConcurrency: integer('max_concurrency').notNull().default(1),
    maxRequestsPerSecond: real('max_requests_per_second').notNull().default(1),
    approvedBy: uuid('approved_by').references(() => users.id, { onDelete: 'set null' }),
    approvedAt: ts('approved_at'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    index('assessment_scopes_engagement_version_idx').on(t.engagementId, t.version),
    index('assessment_scopes_window_idx').on(t.windowStart, t.windowEnd),
  ],
);

export const responseActions = pgTable(
  'response_actions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    kind: responseActionKindEnum('kind').notNull(),
    status: responseActionStatusEnum('status').notNull().default('recommended'),
    incidentId: uuid('incident_id').references(() => incidents.id, { onDelete: 'set null' }),
    targetType: text('target_type').notNull(),
    targetRef: text('target_ref').notNull(),
    triggeringEvidence: text('triggering_evidence').array().notNull().default([]),
    proposedBy: uuid('proposed_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    requiredApprovals: integer('required_approvals').notNull().default(1),
    executedBy: uuid('executed_by').references(() => users.id, { onDelete: 'set null' }),
    executedAt: ts('executed_at'),
    expiresAt: ts('expires_at'),
    rollbackPlan: text('rollback_plan').notNull().default(''),
    justification: text('justification').notNull().default(''),
    parameters: jsonb('parameters').$type<Record<string, unknown>>().notNull().default({}),
    rolledBackAt: ts('rolled_back_at'),
    verificationResult: text('verification_result').notNull().default('not_run'),
    result: jsonb('result').$type<Record<string, unknown>>().notNull().default({}),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('response_actions_status_idx').on(t.status, t.createdAt),
    index('response_actions_incident_idx').on(t.incidentId),
    index('response_actions_expires_idx').on(t.expiresAt),
  ],
);

export const approvals = pgTable(
  'approvals',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    subjectType: approvalSubjectEnum('subject_type').notNull(),
    subjectId: uuid('subject_id').notNull(),
    /** Version of the subject (e.g. engagement scope) the decision covers; null for unversioned subjects. */
    subjectVersion: integer('subject_version'),
    approverId: uuid('approver_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    decision: approvalDecisionEnum('decision').notNull(),
    justification: text('justification').notNull().default(''),
    decidedAt: ts('decided_at').notNull().defaultNow(),
  },
  (t) => [
    index('approvals_subject_idx').on(t.subjectType, t.subjectId),
    index('approvals_approver_idx').on(t.approverId),
  ],
);

export const retentionPolicies = pgTable('retention_policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  dataClass: retentionDataClassEnum('data_class').notNull().unique(),
  retentionDays: integer('retention_days').notNull(),
  legalHold: boolean('legal_hold').notNull().default(false),
  updatedBy: uuid('updated_by').references(() => users.id, { onDelete: 'set null' }),
  updatedAt: ts('updated_at').notNull().defaultNow(),
});
