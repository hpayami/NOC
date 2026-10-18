import { z } from 'zod';
import {
  DetectionCoverage,
  DetectionRuleDetail,
  DetectionValidation,
  RuleDeploymentState,
  type CoverageStatus,
  type DetectionValidationStatus,
  type ValidationVerdict,
} from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import type { MessageKey } from '@/i18n/messages';
import { ValidateForm } from './validate-form';

export const dynamic = 'force-dynamic';
const PERIODS = [7, 30, 90] as const;
const Validations = z.object({ items: z.array(DetectionValidation) });
const Rules = z.object({ items: z.array(DetectionRuleDetail), nextCursor: z.string().nullable() });
const Deployment = z.object({ items: z.array(RuleDeploymentState) });
const VERDICT_LABEL: Record<ValidationVerdict, MessageKey> = {
  passed: 'bt.verdict.passed',
  failed: 'bt.verdict.failed',
  inconclusive: 'bt.verdict.inconclusive',
};
const VERDICT_TONE: Record<ValidationVerdict, string> = {
  passed: 'text-ok',
  failed: 'text-sev-high',
  inconclusive: 'text-sev-medium',
};
const VSTATUS_LABEL: Record<DetectionValidationStatus, MessageKey> = {
  queued: 'bt.vstatus.queued',
  dispatched: 'bt.vstatus.dispatched',
  completed: 'bt.vstatus.completed',
  failed: 'bt.vstatus.failed',
  expired: 'bt.vstatus.expired',
};
const STATUS_LABEL: Record<CoverageStatus, MessageKey> = {
  covered: 'bt.covered',
  deployed_unacknowledged: 'bt.deployed_unacknowledged',
  rule_not_deployed: 'bt.rule_not_deployed',
  uncovered: 'bt.uncovered',
};
const STATUS_TONE: Record<CoverageStatus, string> = {
  covered: 'text-ok',
  deployed_unacknowledged: 'text-sev-medium',
  rule_not_deployed: 'text-sev-low',
  uncovered: 'text-muted',
};

export default async function BlueTeamPage({
  searchParams,
}: {
  searchParams: Promise<{ days?: string; view?: string }>;
}) {
  const { t, locale } = await getI18n();
  const sp = await searchParams;
  const days = (PERIODS as readonly number[]).includes(Number(sp.days)) ? Number(sp.days) : 30;
  const gapsOnly = sp.view === 'gaps';
  const me = await getSessionUser();
  const canChange = me?.permissions.includes('detection_rules.change') ?? false;
  const [c, validations, deployedRules, deployment] = await Promise.all([
    apiFetch(`/api/v1/detection-rules/coverage?days=${days}`, DetectionCoverage),
    apiFetch('/api/v1/detection-rules/validations?limit=50', Validations),
    canChange
      ? apiFetch('/api/v1/detection-rules?lifecycle=deployed&limit=200', Rules)
      : Promise.resolve({ items: [] as z.infer<typeof DetectionRuleDetail>[], nextCursor: null }),
    canChange
      ? apiFetch('/api/v1/detection-rules/deployment', Deployment)
      : Promise.resolve({ items: [] as z.infer<typeof RuleDeploymentState>[] }),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const s = c.summary;
  const isGap = (r: DetectionCoverage['rows'][number]) =>
    r.status !== 'covered' && (r.exposedAssets > 0 || r.observedInPeriod > 0 || r.openAlerts > 0);
  const gaps = c.rows.filter(isGap);
  const rows = gapsOnly ? gaps : c.rows;
  const qs = (over: Record<string, string>) =>
    `/blue-team?${new URLSearchParams({ days: String(days), ...(gapsOnly ? { view: 'gaps' } : {}), ...over })}`;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('bt.title')}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted">{t('bt.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          {PERIODS.map((d) => (
            <a
              key={d}
              href={qs({ days: String(d) })}
              className={`rounded-md border px-3 py-1.5 text-sm ${d === days ? 'border-accent text-fg' : 'border-border text-muted hover:text-fg'}`}
            >
              {fmt.format(d)} {t('rep.days')}
            </a>
          ))}
          <a
            href="/detection-engineering"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
          >
            {t('bt.go_rules')}
          </a>
        </div>
      </header>

      <section
        className="rounded-lg border border-border bg-surface p-4 text-sm"
        data-testid="bt-summary"
      >
        <h2 className="font-medium">{t('bt.summary')}</h2>
        <dl className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs md:grid-cols-4">
          {(
            [
              ['bt.techniques', s.techniques, 'text-fg'],
              ['bt.covered', s.covered, 'text-ok'],
              ['bt.deployed_unacknowledged', s.deployedUnacknowledged, 'text-sev-medium'],
              ['bt.rule_not_deployed', s.ruleNotDeployed, 'text-sev-low'],
              ['bt.uncovered', s.uncovered, 'text-muted'],
              [
                'bt.exposed_uncovered',
                s.exposedUncovered,
                s.exposedUncovered ? 'text-sev-high' : 'text-fg',
              ],
              [
                'bt.observed_uncovered',
                s.observedUncovered,
                s.observedUncovered ? 'text-sev-high' : 'text-fg',
              ],
              ['bt.proven', s.validated, s.validated ? 'text-ok' : 'text-fg'],
            ] as Array<[MessageKey, number, string]>
          ).map(([k, v, tone]) => (
            <div key={k} className="flex justify-between gap-2">
              <dt className="text-muted">{t(k)}</dt>
              <dd className={`tabular-nums ${tone}`}>{fmt.format(v)}</dd>
            </div>
          ))}
          <div className="flex justify-between gap-2">
            <dt className="text-muted">{t('bt.sensors')}</dt>
            <dd className="ltr tabular-nums">
              {fmt.format(s.sensors.enabled)} / {fmt.format(s.sensors.inSync)}
              {Object.keys(s.sensors.byEngine).length ? (
                <span className="text-muted">
                  {' '}
                  (
                  {Object.entries(s.sensors.byEngine)
                    .map(([e, v]) => `${e} ${v.inSync}/${v.enabled}`)
                    .join(', ')}
                  )
                </span>
              ) : null}
            </dd>
          </div>
        </dl>
        <p className="ltr mt-3 text-xs text-muted">
          {t('bt.by_tactic')}:{' '}
          {Object.entries(s.byTactic)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k} ${v.covered}/${v.total}`)
            .join(' · ')}
        </p>
      </section>

      <section aria-labelledby="gaps">
        <h2 id="gaps" className="mb-2 text-lg font-medium">
          {t('bt.gaps')}
        </h2>
        {gaps.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            {t('bt.no_gaps')}
          </p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {gaps.map((r) => (
              <li
                key={r.technique}
                className="rounded-md border border-sev-high/40 bg-surface px-3 py-1.5 text-xs"
              >
                <span className="ltr font-medium">{r.technique}</span>
                <span className="ms-2 text-muted">{r.name ?? t('bt.unknown_technique')}</span>
                <span className="ltr ms-2 text-muted">
                  {r.exposedAssets ? `exposed ${r.exposedAssets}` : ''}
                  {r.observedInPeriod ? ` observed ${r.observedInPeriod}` : ''}
                  {r.openAlerts ? ` alerts ${r.openAlerts}` : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="techniques" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="techniques" className="text-lg font-medium">
            {t('bt.all')} <span className="text-sm text-muted">({fmt.format(rows.length)})</span>
          </h2>
          <div className="flex gap-2 text-sm">
            <a
              href={qs({ view: 'all' })}
              className={`rounded-md border px-3 py-1 ${!gapsOnly ? 'border-accent' : 'border-border text-muted'}`}
            >
              {t('bt.filter_all')}
            </a>
            <a
              href={qs({ view: 'gaps' })}
              className={`rounded-md border px-3 py-1 ${gapsOnly ? 'border-accent' : 'border-border text-muted'}`}
            >
              {t('bt.filter_gaps')}
            </a>
          </div>
        </div>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">{t('bt.technique')}</th>
                <th className="px-3 py-2 text-start">{t('bt.name')}</th>
                <th className="px-3 py-2 text-start">{t('bt.tactic')}</th>
                <th className="px-3 py-2 text-start">{t('bt.status')}</th>
                <th className="px-3 py-2 text-start">{t('bt.rules')}</th>
                <th className="px-3 py-2 text-start">{t('bt.rules_proven')}</th>
                <th className="px-3 py-2 text-start">{t('bt.sensors_in_sync')}</th>
                <th className="px-3 py-2 text-start">{t('bt.observed')}</th>
                <th className="px-3 py-2 text-start">{t('bt.open_alerts')}</th>
                <th className="px-3 py-2 text-start">{t('bt.exposed_assets')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.technique} className="border-t border-border">
                  <td className="ltr px-3 py-2 text-xs font-medium">{r.technique}</td>
                  <td className="ltr px-3 py-2 text-xs">
                    {r.name ?? <span className="text-muted">{t('bt.unknown_technique')}</span>}
                  </td>
                  <td className="ltr px-3 py-2 text-xs text-muted">{r.tactic ?? '—'}</td>
                  <td className={`px-3 py-2 text-xs ${STATUS_TONE[r.status]}`}>
                    {t(STATUS_LABEL[r.status])}
                  </td>
                  <td className="ltr px-3 py-2 text-xs tabular-nums">
                    {r.rules.deployed} / {r.rules.total}
                  </td>
                  <td
                    className={`px-3 py-2 text-xs tabular-nums ${r.rules.proven ? 'text-ok' : ''}`}
                  >
                    {fmt.format(r.rules.proven)}
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">{fmt.format(r.sensorsInSync)}</td>
                  <td className="px-3 py-2 text-xs tabular-nums">
                    {fmt.format(r.observedInPeriod)}
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">{fmt.format(r.openAlerts)}</td>
                  <td
                    className={`px-3 py-2 text-xs tabular-nums ${r.exposedAssets && r.status !== 'covered' ? 'text-sev-high' : ''}`}
                  >
                    {fmt.format(r.exposedAssets)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="validations" className="space-y-3">
        <h2 id="validations" className="text-lg font-medium">
          {t('bt.validations')}
        </h2>
        {validations.items.length === 0 ? (
          <p
            className="rounded-lg border border-border bg-surface p-4 text-sm text-muted"
            data-testid="bt-no-validations"
          >
            {t('bt.no_validations')}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('bt.requested')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.rule')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.sensor')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.sample')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.status')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.verdict')}</th>
                  <th className="px-3 py-2 text-start">{t('bt.fired')}</th>
                </tr>
              </thead>
              <tbody>
                {validations.items.map((v) => (
                  <tr key={v.id} className="border-t border-border align-top">
                    <td className="px-3 py-2 text-xs">{when.format(new Date(v.createdAt))}</td>
                    <td className="ltr px-3 py-2 text-xs">
                      {v.ruleName}
                      <span className="block text-[10px] text-muted">{v.ruleExternalId}</span>
                    </td>
                    <td className="ltr px-3 py-2 text-xs">{v.sensorName}</td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{v.sampleRef}</td>
                    <td className="px-3 py-2 text-xs">{t(VSTATUS_LABEL[v.status])}</td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${v.verdict ? VERDICT_TONE[v.verdict] : 'text-muted'}`}
                    >
                      {v.verdict ? t(VERDICT_LABEL[v.verdict]) : '—'}
                      {v.error ? (
                        <span className="ltr block text-[10px] font-normal text-muted">
                          {v.error}
                        </span>
                      ) : null}
                    </td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">
                      {v.firedSids.length ? v.firedSids.slice(0, 8).join(', ') : '—'}
                      {v.firedSids.length > 8 ? ` +${v.firedSids.length - 8}` : ''}
                      {v.engineVersion ? (
                        <span className="block text-[10px] text-muted">
                          suricata {v.engineVersion}
                        </span>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {canChange ? (
          <ValidateForm
            rules={deployedRules.items.map((r) => ({
              id: r.id,
              label: `${r.externalId} ${r.name}`,
            }))}
            sensors={deployment.items
              .filter((d) => d.engine === 'suricata')
              .map((d) => ({
                id: d.sensorId,
                label: `${d.sensorName}${d.inSync ? '' : ' (bundle not acknowledged)'}`,
              }))}
            labels={{
              heading: t('bt.validate'),
              hint: t('bt.validations_hint'),
              rule: t('bt.rule'),
              sensor: t('bt.sensor'),
              sample: t('bt.sample'),
              note: t('bt.note'),
              submit: t('bt.validate'),
              queued: t('bt.queued'),
              noRules: t('bt.no_deployed_rules'),
              noSensors: t('bt.no_suricata_sensors'),
            }}
          />
        ) : null}
      </section>

      <section className="rounded-lg border border-border bg-surface p-4 text-sm">
        <h2 className="font-medium">{t('bt.limitations')}</h2>
        <ul className="ltr mt-1 list-disc space-y-0.5 ps-5 text-xs text-muted">
          {c.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
