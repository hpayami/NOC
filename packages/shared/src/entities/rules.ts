import { z } from 'zod';
import { Id, ShortText, Timestamp } from '../common';
import { RuleLifecycle, RuleSource, Severity } from '../enums';
import { DetectionRule } from './secops';

export const RULES_IMPORT_MAX_BYTES = 2 * 1024 * 1024;

export const ImportRulesRequest = z.strictObject({
  source: RuleSource.exclude(['zeek_script', 'sigma']),
  ruleSet: ShortText,
  /** Licence under which the rules are used; required so the registry never holds unlicensed content. */
  license: ShortText,
  content: z.string().min(1).max(RULES_IMPORT_MAX_BYTES),
});
export type ImportRulesRequest = z.infer<typeof ImportRulesRequest>;

export const ImportRulesResponse = z.strictObject({
  parsed: z.number().int().nonnegative(),
  imported: z.number().int().nonnegative(),
  updated: z.number().int().nonnegative(),
  unchanged: z.number().int().nonnegative(),
  errors: z
    .array(z.strictObject({ line: z.number().int().positive(), message: z.string().max(256) }))
    .max(20),
  errorCount: z.number().int().nonnegative(),
});
export type ImportRulesResponse = z.infer<typeof ImportRulesResponse>;

export const DetectionRuleDetail = DetectionRule.extend({
  enabled: z.boolean(),
  action: z.string().max(16).nullable(),
  classtype: z.string().max(64).nullable(),
  ruleSet: z.string().max(256).nullable(),
  content: z.string().max(8192).nullable(),
  importedBy: Id.nullable(),
  createdAt: Timestamp,
});
export type DetectionRuleDetail = z.infer<typeof DetectionRuleDetail>;

export const RuleListQuery = z.strictObject({
  lifecycle: RuleLifecycle.optional(),
  source: RuleSource.optional(),
  severity: Severity.optional(),
  q: z.string().trim().min(1).max(128).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(512).optional(),
});
export type RuleListQuery = z.infer<typeof RuleListQuery>;

export const RuleStats = z.strictObject({
  total: z.number().int().nonnegative(),
  byLifecycle: z.record(RuleLifecycle, z.number().int().nonnegative()),
  bySource: z.record(RuleSource, z.number().int().nonnegative()),
  enabled: z.number().int().nonnegative(),
  withTechniques: z.number().int().nonnegative(),
  generatedAt: Timestamp,
});
export type RuleStats = z.infer<typeof RuleStats>;

/** Payload of the live alert stream (SSE). Small on purpose; clients re-fetch the queue. */
export const AlertStreamEvent = z.strictObject({
  kind: z.enum(['created', 'updated', 'triaged']),
  alertId: Id,
  severity: Severity,
  title: z.string().max(256),
  at: Timestamp,
});
export type AlertStreamEvent = z.infer<typeof AlertStreamEvent>;
