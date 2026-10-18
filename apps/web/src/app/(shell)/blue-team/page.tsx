import { DetectionCoverage, type CoverageStatus } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import type { MessageKey } from '@/i18n/messages';

export const dynamic = 'force-dynamic';
const PERIODS = [7, 30, 90] as const;
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
  const c = await apiFetch(`/api/v1/detection-rules/coverage?days=${days}`, DetectionCoverage);
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
