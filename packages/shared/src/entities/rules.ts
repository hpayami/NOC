import { z } from 'zod';
import { SiteKey } from './sites';
import { Id, Sha256, ShortText, Timestamp } from '../common';
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
  /** Deployment targets by site key; empty = every sensor of the matching engine. */
  sites: z.array(z.string().max(32)),
  action: z.string().max(16).nullable(),
  classtype: z.string().max(64).nullable(),
  ruleSet: z.string().max(256).nullable(),
  content: z.string().max(8192).nullable(),
  importedBy: Id.nullable(),
  createdAt: Timestamp,
});
export type DetectionRuleDetail = z.infer<typeof DetectionRuleDetail>;

export const RuleTargetsRequest = z.strictObject({
  sites: z.array(SiteKey).max(64),
});
export type RuleTargetsRequest = z.infer<typeof RuleTargetsRequest>;

export const RuleLifecycleRequest = z.strictObject({
  lifecycle: z.enum(['disabled', 'retired']),
});

export const BundleEngineValues = ['suricata', 'zeek'] as const;
export const BundleEngine = z.enum(BundleEngineValues);
export type BundleEngine = z.infer<typeof BundleEngine>;

export const RuleBundleEntry = z.strictObject({
  id: Id,
  source: RuleSource,
  externalId: z.string().max(128),
  revision: z.number().int().positive(),
  contentSha256: Sha256,
  content: z.string().max(8192),
});
export type RuleBundleEntry = z.infer<typeof RuleBundleEntry>;

/** What a sensor fetches: the deployed, enabled rules targeted at its engine and site. */
export const RuleBundle = z.strictObject({
  engine: BundleEngine,
  sensorId: Id,
  site: z.string().max(32).nullable(),
  generatedAt: Timestamp,
  /** Digest of the canonical manifest (source, id, revision, content hash per rule). */
  bundleSha256: Sha256,
  ruleCount: z.number().int().nonnegative(),
  rules: z.array(RuleBundleEntry).max(20000),
});
export type RuleBundle = z.infer<typeof RuleBundle>;

/** Per-sensor deployment state: what the registry expects vs what the sensor last acknowledged. */
export const RuleDeploymentState = z.strictObject({
  sensorId: Id,
  sensorName: ShortText,
  kind: z.string().max(32),
  site: z.string().max(32).nullable(),
  engine: BundleEngine.nullable(),
  expectedBundleSha256: Sha256.nullable(),
  expectedRuleCount: z.number().int().nonnegative(),
  appliedBundleSha256: Sha256.nullable(),
  appliedAt: Timestamp.nullable(),
  lastHeartbeatAt: Timestamp.nullable(),
  /** True only when the sensor acknowledged exactly the current bundle. */
  inSync: z.boolean(),
});
export type RuleDeploymentState = z.infer<typeof RuleDeploymentState>;

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
