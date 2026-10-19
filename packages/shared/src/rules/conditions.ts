import { IPS_HEARTBEAT_MAX_AGE_SECONDS } from '../entities/ips';
import type { ConditionCheck, PlatformCondition } from '../entities/operations';

export interface ConditionInput {
  sensors: ReadonlyArray<{
    name: string;
    enabled: boolean;
    lastHeartbeatAt: Date | null;
    latestHealth: string | null;
  }>;
  /** Rule-bundle deployment state per enabled sensor that consumes registry rules. */
  bundles: ReadonlyArray<{ sensorName: string; inSync: boolean; expectedRuleCount: number }>;
  ipsPolicies: ReadonlyArray<{
    name: string;
    status: string;
    expiresAt: Date | null;
    disableCause: string | null;
    disabledAt: Date | null;
  }>;
  /** null = the check could not run (e.g. the status probe itself failed). */
  analysis: { reachable: boolean; detail: string | null } | null;
  pending: { ipsPolicies: number; engagements: number; responseActions: number };
  uncataloguedCves: readonly string[];
  assets: { total: number; unmonitored: number };
  /** Deployed rules whose latest validation failed, and schedules the scheduler could not queue. */
  validations?: { failedRules: readonly string[]; scheduleErrors: readonly string[] };
}

export const IPS_EXPIRY_WARNING_HOURS = 2;
export const IPS_AUTO_DISABLE_LOOKBACK_HOURS = 24;
export const UNMONITORED_WARNING_RATIO = 0.5;

/**
 * Pure evaluation of platform conditions. Every check appears in `checks` with `ok`, `failing`
 * or `unavailable`; conditions are only the failing ones, with counts and a workspace link.
 */
export function evaluateConditions(
  input: ConditionInput,
  now: Date,
): { conditions: PlatformCondition[]; checks: ConditionCheck[] } {
  const conditions: PlatformCondition[] = [];
  const checks: ConditionCheck[] = [];
  const check = (id: string, failing: PlatformCondition | null, okDetail: string) => {
    if (failing) {
      conditions.push(failing);
      checks.push({ id, status: 'failing', detail: failing.detail.slice(0, 512) });
    } else checks.push({ id, status: 'ok', detail: okDetail });
  };
  const list = (xs: readonly string[], max = 8) =>
    xs.length <= max ? xs.join(', ') : `${xs.slice(0, max).join(', ')} +${xs.length - max}`;

  const enabled = input.sensors.filter((s) => s.enabled);
  const silent = enabled.filter(
    (s) =>
      !s.lastHeartbeatAt ||
      (now.getTime() - s.lastHeartbeatAt.getTime()) / 1000 > IPS_HEARTBEAT_MAX_AGE_SECONDS,
  );
  check(
    'sensors_silent',
    silent.length
      ? {
          id: 'sensors_silent',
          severity: 'critical',
          title: 'Sensors silent',
          detail: `${silent.length} enabled sensor(s) sent no heartbeat in the last ${IPS_HEARTBEAT_MAX_AGE_SECONDS} s: ${list(silent.map((s) => s.name))}`,
          count: silent.length,
          link: '/nids',
        }
      : null,
    `${enabled.length} enabled sensor(s) heartbeating`,
  );
  const unhealthy = enabled.filter(
    (s) => !silent.includes(s) && s.latestHealth !== null && s.latestHealth !== 'healthy',
  );
  check(
    'sensors_unhealthy',
    unhealthy.length
      ? {
          id: 'sensors_unhealthy',
          severity: 'warning',
          title: 'Sensors unhealthy',
          detail: `${unhealthy.length} sensor(s) report degraded or failed health: ${list(unhealthy.map((s) => `${s.name} (${s.latestHealth})`))}`,
          count: unhealthy.length,
          link: '/nids',
        }
      : null,
    'all heartbeating sensors report healthy',
  );
  const outOfSync = input.bundles.filter((b) => !b.inSync);
  check(
    'rule_bundles_out_of_sync',
    outOfSync.length
      ? {
          id: 'rule_bundles_out_of_sync',
          severity: 'warning',
          title: 'Rule bundles not acknowledged',
          detail: `${outOfSync.length} sensor(s) are not running the current rule bundle: ${list(outOfSync.map((b) => b.sensorName))}`,
          count: outOfSync.length,
          link: '/detection-engineering',
        }
      : null,
    input.bundles.length
      ? `${input.bundles.length} sensor(s) on the current bundle`
      : 'no rule-consuming sensors',
  );
  const expiring = input.ipsPolicies.filter(
    (p) =>
      p.status === 'enabled' &&
      p.expiresAt !== null &&
      p.expiresAt.getTime() - now.getTime() < IPS_EXPIRY_WARNING_HOURS * 3_600_000,
  );
  check(
    'ips_policies_expiring',
    expiring.length
      ? {
          id: 'ips_policies_expiring',
          severity: 'warning',
          title: 'Inline prevention expiring',
          detail: `${expiring.length} enabled policy(ies) expire within ${IPS_EXPIRY_WARNING_HOURS} h and will return their sensor to detect-only: ${list(expiring.map((p) => p.name))}`,
          count: expiring.length,
          link: '/nips',
        }
      : null,
    `${input.ipsPolicies.filter((p) => p.status === 'enabled').length} enabled policy(ies), none expiring soon`,
  );
  const autoDisabled = input.ipsPolicies.filter(
    (p) =>
      p.disableCause === 'sensor_unhealthy' &&
      p.disabledAt !== null &&
      now.getTime() - p.disabledAt.getTime() < IPS_AUTO_DISABLE_LOOKBACK_HOURS * 3_600_000,
  );
  check(
    'ips_auto_disabled',
    autoDisabled.length
      ? {
          id: 'ips_auto_disabled',
          severity: 'critical',
          title: 'Inline prevention dropped by the watchdog',
          detail: `${autoDisabled.length} policy(ies) were returned to detect-only in the last ${IPS_AUTO_DISABLE_LOOKBACK_HOURS} h because the sensor stopped qualifying: ${list(autoDisabled.map((p) => p.name))}`,
          count: autoDisabled.length,
          link: '/nips',
        }
      : null,
    'no watchdog disables in the last 24 h',
  );
  if (input.analysis === null)
    checks.push({ id: 'analysis_reachable', status: 'unavailable', detail: 'probe did not run' });
  else
    check(
      'analysis_reachable',
      input.analysis.reachable
        ? null
        : {
            id: 'analysis_unreachable',
            severity: 'warning',
            title: 'Analysis service unreachable',
            detail: `Advisory ML scoring is unavailable${input.analysis.detail ? `: ${input.analysis.detail}` : ''}`,
            count: 1,
            link: '/ml-analytics',
          },
      'analysis service reachable',
    );
  const pending =
    input.pending.ipsPolicies + input.pending.engagements + input.pending.responseActions;
  check(
    'approvals_pending',
    pending
      ? {
          id: 'approvals_pending',
          severity: 'info',
          title: 'Approvals waiting',
          detail: `${input.pending.ipsPolicies} IPS policy(ies), ${input.pending.engagements} engagement(s), ${input.pending.responseActions} response action(s) await a decision`,
          count: pending,
          link: '/nips',
        }
      : null,
    'nothing awaits approval',
  );
  check(
    'cves_uncatalogued',
    input.uncataloguedCves.length
      ? {
          id: 'cves_uncatalogued',
          severity: 'info',
          title: 'CVEs without catalogue entry',
          detail: `${input.uncataloguedCves.length} CVE(s) referenced by findings are not in the vulnerability catalogue: ${list(input.uncataloguedCves)}`,
          count: input.uncataloguedCves.length,
          link: '/vulnerabilities',
        }
      : null,
    'every referenced CVE is catalogued',
  );
  const v = input.validations ?? { failedRules: [], scheduleErrors: [] };
  const failing = v.failedRules.length + v.scheduleErrors.length;
  check(
    'detection_validation_failures',
    failing
      ? {
          id: 'detection_validation_failures',
          severity: 'warning',
          title: 'Detection validation failing',
          detail: `${v.failedRules.length} deployed rule(s) did not fire on their sample: ${list(v.failedRules)}${v.scheduleErrors.length ? `; ${v.scheduleErrors.length} schedule(s) could not queue: ${list(v.scheduleErrors)}` : ''}`,
          count: failing,
          link: '/blue-team',
        }
      : null,
    'no failed validation or stuck schedule',
  );
  const ratio = input.assets.total ? input.assets.unmonitored / input.assets.total : 0;
  check(
    'assets_unmonitored',
    input.assets.total && ratio > UNMONITORED_WARNING_RATIO
      ? {
          id: 'assets_unmonitored',
          severity: 'warning',
          title: 'Most assets unmonitored',
          detail: `${input.assets.unmonitored} of ${input.assets.total} assets have no detection coverage; their risk is unknown, not low`,
          count: input.assets.unmonitored,
          link: '/assets',
        }
      : null,
    input.assets.total
      ? `${input.assets.unmonitored}/${input.assets.total} assets unmonitored`
      : 'no assets recorded',
  );
  const rank = { critical: 0, warning: 1, info: 2 } as const;
  conditions.sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
  return { conditions, checks };
}

/** Changes in this value are what a channel gets told about; stable text keeps notifications quiet. */
export const conditionFingerprint = (c: PlatformCondition): string =>
  `${c.id}:${c.severity}:${c.count}`;
