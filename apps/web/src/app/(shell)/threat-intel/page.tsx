import { z } from 'zod';
import {
  IndicatorMatch,
  IndicatorRecord,
  IndicatorTypeValues,
  ThreatIntelStats,
  type Severity,
} from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { ImportIndicatorsForm, RevokeButton } from './controls';

export const dynamic = 'force-dynamic';
const Indicators = z.object({ items: z.array(IndicatorRecord), total: z.number().int() });
const Matches = z.object({ items: z.array(IndicatorMatch) });
const SEV: Record<Severity, string> = {
  info: 'text-sev-info',
  low: 'text-sev-low',
  medium: 'text-sev-medium',
  high: 'text-sev-high',
  critical: 'text-sev-critical',
};
const TYPES = new Set<string>(IndicatorTypeValues);

export default async function ThreatIntelPage({
  searchParams,
}: {
  searchParams: Promise<{ type?: string; q?: string; inactive?: string }>;
}) {
  const { t, locale } = await getI18n();
  const sp = await searchParams;
  const type = sp.type && TYPES.has(sp.type) ? sp.type : '';
  const q = (sp.q ?? '').slice(0, 256);
  const inactive = sp.inactive === '1';
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('threat_intel.manage') ?? false;
  const qs = new URLSearchParams({ limit: '200' });
  if (type) qs.set('type', type);
  if (q) qs.set('q', q);
  if (inactive) qs.set('includeInactive', 'true');
  const [stats, indicators, matches] = await Promise.all([
    apiFetch('/api/v1/threat-intel/stats', ThreatIntelStats),
    apiFetch(`/api/v1/threat-intel/indicators?${qs}`, Indicators),
    apiFetch('/api/v1/threat-intel/matches?limit=100', Matches),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm';

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{t('ti.title')}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">{t('ti.subtitle')}</p>
      </header>

      <section
        className="rounded-lg border border-border bg-surface p-4 text-sm"
        data-testid="ti-stats"
      >
        <h2 className="font-medium">{t('ti.stats')}</h2>
        {stats.total === 0 ? (
          <p className="mt-1 text-xs text-muted">{t('ti.none')}</p>
        ) : (
          <>
            <p className="mt-1 text-xs text-muted">
              {t('ti.active')}: <span className="text-fg">{fmt.format(stats.active)}</span> ·{' '}
              {t('ti.expired')}: {fmt.format(stats.expired)} · {t('ti.revoked')}:{' '}
              {fmt.format(stats.revoked)} · {t('ti.last_import')}:{' '}
              {stats.lastImportAt ? when.format(new Date(stats.lastImportAt)) : '—'} ·{' '}
              {t('ti.matches_24h')}:{' '}
              <span className={stats.matches24h ? 'text-sev-high' : 'text-fg'}>
                {fmt.format(stats.matches24h)}
              </span>{' '}
              · {t('ti.last_match')}:{' '}
              {stats.lastMatchAt ? when.format(new Date(stats.lastMatchAt)) : '—'}
            </p>
            <p className="ltr mt-1 text-xs text-muted">
              {Object.entries(stats.byType)
                .map(([k, v]) => `${k}: ${v}`)
                .join(' · ')}
            </p>
            <p className="ltr mt-1 text-xs text-muted">
              {t('ti.sources')}: {stats.sources.map((s) => `${s.source} (${s.active})`).join(', ')}
            </p>
          </>
        )}
      </section>

      {canManage ? (
        <ImportIndicatorsForm
          labels={{
            heading: t('ti.import'),
            hint: t('ti.import_hint'),
            format: t('ti.import_format'),
            source: t('ti.import_source'),
            severity: t('ti.import_severity'),
            submit: t('ti.import_submit'),
            result: t('ti.import_result'),
          }}
        />
      ) : null}

      <section aria-labelledby="matches">
        <h2 id="matches" className="mb-2 text-lg font-medium">
          {t('ti.matches')}
        </h2>
        {matches.items.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            {t('ti.no_matches')}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('ti.observed')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.type')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.value')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.field')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.source')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.alert')}</th>
                </tr>
              </thead>
              <tbody>
                {matches.items.map((m) => (
                  <tr key={m.id} className="border-t border-border">
                    <td className="px-3 py-2 text-xs">{when.format(new Date(m.observedAt))}</td>
                    <td className={`ltr px-3 py-2 text-xs font-medium ${SEV[m.severity]}`}>
                      {m.type}
                    </td>
                    <td className="ltr max-w-xs truncate px-3 py-2 text-xs">{m.value}</td>
                    <td className="ltr px-3 py-2 text-xs text-muted">
                      {m.matchedField} = {m.matchedValue}
                    </td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{m.source}</td>
                    <td className="px-3 py-2 text-xs">
                      {m.alertId ? (
                        <a href={`/soc-alerts/${m.alertId}`} className="underline">
                          {t('ti.alert')}
                        </a>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="indicators" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 id="indicators" className="text-lg font-medium">
            {t('ti.indicators')}{' '}
            <span className="text-sm text-muted">({fmt.format(indicators.total)})</span>
          </h2>
          <form method="get" className="flex flex-wrap items-center gap-2">
            <select
              name="type"
              defaultValue={type}
              className={`ltr ${input}`}
              aria-label={t('ti.type')}
            >
              <option value="">{t('ti.all_types')}</option>
              {IndicatorTypeValues.map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
            <input
              name="q"
              defaultValue={q}
              placeholder={t('ti.search')}
              maxLength={256}
              className={`ltr ${input}`}
            />
            {inactive ? <input type="hidden" name="inactive" value="1" /> : null}
            <button type="submit" className="rounded-md border border-border px-3 py-1.5 text-sm">
              {t('ti.filter')}
            </button>
            <a
              href={`/threat-intel?${new URLSearchParams({ ...(type ? { type } : {}), ...(q ? { q } : {}), ...(inactive ? {} : { inactive: '1' }) })}`}
              className="text-xs text-muted underline"
            >
              {inactive ? t('ti.show_active') : t('ti.show_inactive')}
            </a>
          </form>
        </div>
        {indicators.items.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            {t('ti.no_indicators')}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('ti.type')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.value')}</th>
                  <th className="px-3 py-2 text-start">{t('alerts.severity')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.confidence')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.source')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.matches_count')}</th>
                  <th className="px-3 py-2 text-start">{t('ti.expires')}</th>
                  {canManage ? <th className="px-3 py-2 text-start">—</th> : null}
                </tr>
              </thead>
              <tbody>
                {indicators.items.map((i) => (
                  <tr
                    key={i.id}
                    className={`border-t border-border ${i.revoked ? 'opacity-60' : ''}`}
                  >
                    <td className="ltr px-3 py-2 text-xs">{i.type}</td>
                    <td
                      className="ltr max-w-xs truncate px-3 py-2 text-xs"
                      title={i.description ?? undefined}
                    >
                      {i.value}
                      {i.tags.length ? (
                        <span className="ms-2 text-muted">{i.tags.join(', ')}</span>
                      ) : null}
                    </td>
                    <td className={`ltr px-3 py-2 text-xs font-medium ${SEV[i.severity]}`}>
                      {i.severity}
                    </td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">{i.confidence}</td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{i.source}</td>
                    <td className="px-3 py-2 text-xs tabular-nums">
                      {fmt.format(i.matchCount)}
                      {i.lastMatchedAt ? (
                        <span className="text-muted">
                          {' '}
                          · {when.format(new Date(i.lastMatchedAt))}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted">
                      {i.revoked
                        ? t('ti.revoked')
                        : i.expiresAt
                          ? when.format(new Date(i.expiresAt))
                          : '—'}
                    </td>
                    {canManage ? (
                      <td className="px-3 py-2">
                        {!i.revoked ? (
                          <RevokeButton
                            id={i.id}
                            labels={{ revoke: t('ti.revoke'), done: t('ti.revoked_ok') }}
                          />
                        ) : null}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
