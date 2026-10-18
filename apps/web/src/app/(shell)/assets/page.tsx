import { z } from 'zod';
import { Asset, AssetCoverageSummary, type AssuranceState, type CoverageState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(Asset), nextCursor: z.string().nullable() });

const COVERAGE_LABEL: Record<CoverageState, MessageKey> = {
  monitored: 'coverage.monitored',
  partial: 'coverage.partial',
  unmonitored: 'coverage.unmonitored',
  unknown: 'coverage.unknown',
};
const COVERAGE_STYLE: Record<CoverageState, string> = {
  monitored: 'text-ok',
  partial: 'text-sev-medium',
  unmonitored: 'text-sev-high',
  unknown: 'text-muted',
};
const ASSURANCE_LABEL: Record<AssuranceState, MessageKey> = {
  no_threat_detected: 'assurance.no_threat_detected',
  detection_unavailable: 'assurance.detection_unavailable',
  asset_not_monitored: 'assurance.asset_not_monitored',
  telemetry_incomplete: 'assurance.telemetry_incomplete',
  sensor_unhealthy: 'assurance.sensor_unhealthy',
  assessment_not_performed: 'assurance.assessment_not_performed',
  assessment_with_findings: 'assurance.assessment_with_findings',
};

export default async function AssetsPage({
  searchParams,
}: {
  searchParams: Promise<{ cursor?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { cursor } = await searchParams;
  const qs = new URLSearchParams({ limit: '50', ...(cursor ? { cursor } : {}) });
  const [summary, page] = await Promise.all([
    apiFetch('/api/v1/assets/coverage', AssetCoverageSummary),
    apiFetch(`/api/v1/assets?${qs}`, Page),
  ]);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const coverageKeys = Object.keys(COVERAGE_LABEL) as CoverageState[];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{t('assets.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('assets.subtitle')}</p>
      </header>

      <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <li className="rounded-lg border border-border bg-surface p-4">
          <p className="text-xs text-muted">{t('assets.total')}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">{fmt.format(summary.total)}</p>
        </li>
        {coverageKeys.map((k) => (
          <li key={k} className="rounded-lg border border-border bg-surface p-4">
            <p className={`text-xs ${COVERAGE_STYLE[k]}`}>{t(COVERAGE_LABEL[k])}</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">
              {fmt.format(summary.byCoverage[k])}
            </p>
          </li>
        ))}
        <li className="rounded-lg border border-border bg-surface p-4">
          <p className="text-xs text-sev-medium">{t('assets.unresolved')}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">
            {fmt.format(summary.unresolvedObservations)}
          </p>
        </li>
      </ul>

      {page.items.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface p-6">
          <p className="font-medium">{t('assets.empty')}</p>
          <p className="mt-1 text-sm text-muted">{t('assets.empty_hint')}</p>
          <code className="ltr mt-3 block rounded bg-surface-2 p-3 text-xs text-muted">
            POST /api/v1/assets/observations
          </code>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">{t('assets.hostname')}</th>
                <th className="px-3 py-2 text-start">{t('assets.class')}</th>
                <th className="px-3 py-2 text-start">{t('assets.ips')}</th>
                <th className="px-3 py-2 text-start">{t('assets.coverage')}</th>
                <th className="px-3 py-2 text-start">{t('assets.assurance')}</th>
                <th className="px-3 py-2 text-start">{t('assets.confidence')}</th>
                <th className="px-3 py-2 text-start">{t('assets.last_seen')}</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((a) => (
                <tr key={a.id} className="border-t border-border align-top">
                  <td className="px-3 py-2">
                    <span className="ltr">{a.hostname ?? '—'}</span>
                    <span className="ltr block text-[10px] text-muted">{a.id.slice(0, 8)}</span>
                  </td>
                  <td className="ltr px-3 py-2 text-xs">{a.assetClass}</td>
                  <td className="ltr px-3 py-2 text-xs">{a.ipAddresses.join(', ') || '—'}</td>
                  <td className={`px-3 py-2 text-xs ${COVERAGE_STYLE[a.monitoringCoverage]}`}>
                    {t(COVERAGE_LABEL[a.monitoringCoverage])}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {t(ASSURANCE_LABEL[a.assuranceState])}
                  </td>
                  <td className="ltr px-3 py-2 text-xs tabular-nums">
                    {Math.round(a.dataConfidence * 100)}%
                  </td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {when.format(new Date(a.lastSeenAt))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page.nextCursor ? (
        <a
          href={`/assets?cursor=${encodeURIComponent(page.nextCursor)}`}
          className="inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {t('audit.next')} →
        </a>
      ) : null}
    </div>
  );
}
