import type { CoverageStatus, DetectionCoverage, TechniqueCoverageRow } from '../entities/coverage';
import { ATTACK_TECHNIQUES, TECHNIQUE_ID, techniqueInfo } from './attack';

export interface CoverageInput {
  rules: ReadonlyArray<{
    lifecycle: string;
    techniques: readonly string[];
    engine: string;
    validated?: boolean;
  }>;
  sensors: ReadonlyArray<{ engine: string | null; enabled: boolean; inSync: boolean }>;
  /** Technique → events in the period that carried it. */
  observed: Readonly<Record<string, number>>;
  /** Technique → open alerts whose last event carried it. */
  openAlerts: Readonly<Record<string, number>>;
  /** Technique → assets exposing it through an observed listening service. */
  exposed: Readonly<Record<string, number>>;
  periodDays: number;
}

/**
 * Pure coverage computation. A technique is only `covered` when a deployed rule exists *and* an
 * enabled sensor of that rule's engine acknowledged the current bundle — a rule nobody runs
 * detects nothing. Techniques outside the catalogue are kept (named null), never dropped.
 */
export function computeCoverage(input: CoverageInput, now: Date): DetectionCoverage {
  const inSyncByEngine = new Map<string, number>();
  const enabledByEngine = new Map<string, number>();
  for (const s of input.sensors) {
    if (!s.enabled || !s.engine) continue;
    enabledByEngine.set(s.engine, (enabledByEngine.get(s.engine) ?? 0) + 1);
    if (s.inSync) inSyncByEngine.set(s.engine, (inSyncByEngine.get(s.engine) ?? 0) + 1);
  }
  const ids = new Set<string>(Object.keys(ATTACK_TECHNIQUES));
  for (const r of input.rules) {
    if (r.lifecycle === 'retired') continue;
    for (const t of r.techniques) if (TECHNIQUE_ID.test(t)) ids.add(t);
  }
  for (const k of [
    ...Object.keys(input.observed),
    ...Object.keys(input.openAlerts),
    ...Object.keys(input.exposed),
  ])
    if (TECHNIQUE_ID.test(k)) ids.add(k);

  const rows: TechniqueCoverageRow[] = [];
  for (const technique of [...ids].sort()) {
    const rules = { total: 0, deployed: 0, validatedLifecycle: 0, draft: 0, disabled: 0 };
    let proven = 0;
    const deployedEngines = new Set<string>();
    for (const r of input.rules) {
      if (r.lifecycle === 'retired' || !r.techniques.includes(technique)) continue;
      rules.total++;
      if (r.lifecycle === 'deployed') {
        rules.deployed++;
        if (r.validated) proven++;
        deployedEngines.add(r.engine);
      } else if (r.lifecycle === 'validated') rules.validatedLifecycle++;
      else if (r.lifecycle === 'draft') rules.draft++;
      else if (r.lifecycle === 'disabled') rules.disabled++;
    }
    let sensorsInSync = 0;
    for (const e of deployedEngines) sensorsInSync += inSyncByEngine.get(e) ?? 0;
    const status: CoverageStatus =
      rules.deployed > 0
        ? sensorsInSync > 0
          ? 'covered'
          : 'deployed_unacknowledged'
        : rules.total > 0
          ? 'rule_not_deployed'
          : 'uncovered';
    const info = techniqueInfo(technique);
    rows.push({
      technique,
      name: info.name,
      tactic: info.tactic,
      status,
      rules: {
        total: rules.total,
        deployed: rules.deployed,
        validated: rules.validatedLifecycle,
        draft: rules.draft,
        disabled: rules.disabled,
        proven,
      },
      sensorsInSync,
      observedInPeriod: input.observed[technique] ?? 0,
      openAlerts: input.openAlerts[technique] ?? 0,
      exposedAssets: input.exposed[technique] ?? 0,
    });
  }

  const byTactic: Record<string, { total: number; covered: number }> = {};
  for (const r of rows) {
    const key = r.tactic ?? 'unknown';
    byTactic[key] ??= { total: 0, covered: 0 };
    byTactic[key].total++;
    if (r.status === 'covered') byTactic[key].covered++;
  }
  const count = (s: CoverageStatus) => rows.filter((r) => r.status === s).length;
  const enabled = [...enabledByEngine.values()].reduce((a, b) => a + b, 0);
  const inSync = [...inSyncByEngine.values()].reduce((a, b) => a + b, 0);
  return {
    generatedAt: now.toISOString(),
    periodDays: input.periodDays,
    summary: {
      techniques: rows.length,
      covered: count('covered'),
      validated: rows.filter((r) => r.status === 'covered' && r.rules.proven > 0).length,
      deployedUnacknowledged: count('deployed_unacknowledged'),
      ruleNotDeployed: count('rule_not_deployed'),
      uncovered: count('uncovered'),
      exposedUncovered: rows.filter((r) => r.exposedAssets > 0 && r.status !== 'covered').length,
      observedUncovered: rows.filter((r) => r.observedInPeriod > 0 && r.status !== 'covered')
        .length,
      byTactic,
      sensors: {
        enabled,
        inSync,
        byEngine: Object.fromEntries(
          [...enabledByEngine.keys()].map((e) => [
            e,
            { enabled: enabledByEngine.get(e) ?? 0, inSync: inSyncByEngine.get(e) ?? 0 },
          ]),
        ),
      },
    },
    rows,
    limitations: [
      'Coverage is computed from the rule registry and the sensors that acknowledged the current bundle; rules an engine loads outside the registry are not visible here.',
      'A technique is counted as observed only when the engine tagged the event with it (Suricata metadata); untagged detections are not attributed.',
      'Exposure comes from listening services the platform observed on inventoried assets; an unmonitored asset exposes nothing here because nothing is known, not because it is safe.',
      `Observation and alert counts cover the last ${input.periodDays} day(s).`,
    ],
  };
}
