import { z } from 'zod';
import { Timestamp } from '../common';

/**
 * Coverage of one ATT&CK technique by the detection plane.
 *  covered                 — a deployed rule for it is acknowledged by at least one enabled sensor
 *  deployed_unacknowledged — a rule is deployed but no sensor of that engine runs the current bundle
 *  rule_not_deployed       — rules exist (draft/validated/disabled) but none is deployed
 *  uncovered               — no rule in the registry references the technique
 */
export const CoverageStatusValues = [
  'covered',
  'deployed_unacknowledged',
  'rule_not_deployed',
  'uncovered',
] as const;
export const CoverageStatus = z.enum(CoverageStatusValues);
export type CoverageStatus = z.infer<typeof CoverageStatus>;

export const TechniqueCoverageRow = z.strictObject({
  technique: z.string().regex(/^T\d{4}(\.\d{3})?$/),
  /** null when the technique is not in the platform's catalogue (seen in a rule or event only). */
  name: z.string().max(128).nullable(),
  tactic: z.string().max(64).nullable(),
  status: CoverageStatus,
  rules: z.strictObject({
    total: z.number().int().nonnegative(),
    deployed: z.number().int().nonnegative(),
    validated: z.number().int().nonnegative(),
    draft: z.number().int().nonnegative(),
    disabled: z.number().int().nonnegative(),
  }),
  /** Enabled sensors of the rules' engine(s) that acknowledged the current bundle. */
  sensorsInSync: z.number().int().nonnegative(),
  /** Events in the period whose engine tagged this technique. */
  observedInPeriod: z.number().int().nonnegative(),
  /** Open alerts whose last event carries this technique. */
  openAlerts: z.number().int().nonnegative(),
  /** Assets whose observed listening services expose this technique (exposure, not an attack seen). */
  exposedAssets: z.number().int().nonnegative(),
});
export type TechniqueCoverageRow = z.infer<typeof TechniqueCoverageRow>;

export const DetectionCoverage = z.strictObject({
  generatedAt: Timestamp,
  periodDays: z.number().int().positive(),
  summary: z.strictObject({
    techniques: z.number().int().nonnegative(),
    covered: z.number().int().nonnegative(),
    deployedUnacknowledged: z.number().int().nonnegative(),
    ruleNotDeployed: z.number().int().nonnegative(),
    uncovered: z.number().int().nonnegative(),
    /** Techniques exposed by an open service on some asset and not covered — the actionable gap. */
    exposedUncovered: z.number().int().nonnegative(),
    /** Techniques the engines reported in the period while no rule for them is deployed here. */
    observedUncovered: z.number().int().nonnegative(),
    byTactic: z.record(
      z.string(),
      z.strictObject({
        total: z.number().int().nonnegative(),
        covered: z.number().int().nonnegative(),
      }),
    ),
    sensors: z.strictObject({
      enabled: z.number().int().nonnegative(),
      inSync: z.number().int().nonnegative(),
      byEngine: z.record(
        z.string(),
        z.strictObject({
          enabled: z.number().int().nonnegative(),
          inSync: z.number().int().nonnegative(),
        }),
      ),
    }),
  }),
  rows: z.array(TechniqueCoverageRow).max(2000),
  limitations: z.array(z.string().max(512)).max(16),
});
export type DetectionCoverage = z.infer<typeof DetectionCoverage>;

export const CoverageQuery = z.strictObject({
  days: z.coerce.number().int().min(1).max(365).default(30),
});
