import { sql } from 'drizzle-orm';
import {
  cidr,
  index,
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  IpsApplyStateValues,
  IpsPolicyActionValues,
  IpsPolicyModeValues,
  IpsPolicyStatusValues,
} from '@noc/shared';
import { users } from './identity';
import { sensors } from './sensors';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const ipsPolicyModeEnum = pgEnum('ips_policy_mode', IpsPolicyModeValues);
export const ipsPolicyStatusEnum = pgEnum('ips_policy_status', IpsPolicyStatusValues);
export const ipsApplyStateEnum = pgEnum('ips_apply_state', IpsApplyStateValues);
export const ipsPolicyActionEnum = pgEnum('ips_policy_action', IpsPolicyActionValues);

/**
 * Inline-prevention policies. A sensor runs at most one *enabled* policy; everything else is
 * history. Enabling is time-boxed (`expires_at`) and the sensor confirms what it applied.
 */
export const ipsPolicies = pgTable(
  'ips_policies',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    sensorId: uuid('sensor_id')
      .notNull()
      .references(() => sensors.id, { onDelete: 'cascade' }),
    mode: ipsPolicyModeEnum('mode').notNull(),
    action: ipsPolicyActionEnum('action').notNull().default('drop'),
    protectedCidrs: cidr('protected_cidrs').array().notNull().default([]),
    excludedCidrs: cidr('excluded_cidrs').array().notNull().default([]),
    ruleIds: uuid('rule_ids').array().notNull().default([]),
    status: ipsPolicyStatusEnum('status').notNull().default('pending_approval'),
    version: integer('version').notNull().default(0),
    justification: text('justification').notNull().default(''),
    rollbackPlan: text('rollback_plan').notNull().default(''),
    proposedBy: uuid('proposed_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    requiredApprovals: integer('required_approvals').notNull().default(2),
    enabledBy: uuid('enabled_by').references(() => users.id, { onDelete: 'set null' }),
    enabledAt: ts('enabled_at'),
    expiresAt: ts('expires_at'),
    disabledBy: uuid('disabled_by').references(() => users.id, { onDelete: 'set null' }),
    disabledAt: ts('disabled_at'),
    disableReason: text('disable_reason'),
    applyState: ipsApplyStateEnum('apply_state').notNull().default('none'),
    appliedVersion: integer('applied_version'),
    appliedAt: ts('applied_at'),
    applyDetail: text('apply_detail'),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('ips_policies_sensor_status_idx').on(t.sensorId, t.status),
    index('ips_policies_status_expires_idx').on(t.status, t.expiresAt),
    uniqueIndex('ips_policies_one_enabled_per_sensor_idx')
      .on(t.sensorId)
      .where(sql`status = 'enabled'`),
  ],
);
