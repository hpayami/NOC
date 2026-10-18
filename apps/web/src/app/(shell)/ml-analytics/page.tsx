import { z } from 'zod';
import { MlScoreRecord, MlStatus } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { ScoreForms } from './controls';

export const dynamic = 'force-dynamic';
const List = z.object({ items: z.array(MlScoreRecord) });

export default async function MlAnalyticsPage() {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('ml.manage') ?? false;
  const [status, results] = await Promise.all([
    apiFetch('/api/v1/ml/status', MlStatus),
    apiFetch('/api/v1/ml/results?limit=100', List),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const pct = (n: number) => `${Math.round(n * 100)}%`;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('ml.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('ml.subtitle')}</p>
      </header>

      <section
        className="rounded-lg border border-border bg-surface p-5 text-sm"
        aria-labelledby="service"
      >
        <h2 id="service" className="font-medium">
          {t('ml.service')}
        </h2>
        <p className="mt-2 flex flex-wrap items-center gap-3 text-xs">
          <span className="ltr">{status.analysisUrl}</span>
          <span
            className={status.reachable ? 'text-ok' : 'text-sev-high'}
            data-testid="ml-reachable"
          >
            {status.reachable ? t('ml.reachable') : t('ml.unreachable')}
          </span>
          <span className="rounded border border-sev-medium/30 px-1 text-sev-medium">
            {t('ml.advisory_only')}
          </span>
          <span className="text-muted">
            {t('ml.external_apis')}:{' '}
            {status.externalModelApisAllowed === null
              ? '—'
              : status.externalModelApisAllowed
                ? t('common.yes')
                : t('common.no')}
          </span>
        </p>
        {!status.reachable && status.detail ? (
          <p className="ltr mt-1 text-xs text-muted">{status.detail}</p>
        ) : null}
        {status.models.length === 0 ? (
          <p className="mt-3 text-xs text-muted">{t('ml.no_models')}</p>
        ) : (
          <ul className="mt-3 space-y-1 text-xs">
            {status.models.map((m) => (
              <li key={`${m.name}@${m.version}`} className="flex flex-wrap items-center gap-2">
                <span className="ltr font-medium">
                  {m.name}@{m.version}
                </span>
                <span className="ltr">{m.kind}</span>
                <span className="ltr">{m.state}</span>
                <span className="text-muted">
                  {t('ml.evaluation')}: {m.evaluation}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {canManage ? (
        <ScoreForms
          labels={{
            assetId: t('ml.asset_id'),
            score: t('ml.score_one'),
            batch: t('ml.score_batch'),
          }}
        />
      ) : null}

      <section className="space-y-3" aria-labelledby="results">
        <h2 id="results" className="font-medium">
          {t('ml.results')}
        </h2>
        {results.items.length === 0 ? (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm">
            <p>{t('ml.empty')}</p>
            <p className="mt-1 text-xs text-muted">{t('ml.empty_hint')}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('ml.score')}</th>
                  <th className="px-3 py-2 text-start">{t('ml.subject')}</th>
                  <th className="px-3 py-2 text-start">{t('ml.explanation')}</th>
                  <th className="px-3 py-2 text-start">{t('ml.model')}</th>
                  <th className="px-3 py-2 text-start">{t('ml.when')}</th>
                </tr>
              </thead>
              <tbody>
                {results.items.map((r) => (
                  <tr key={r.id} className="border-t border-border align-top">
                    <td
                      className={`ltr px-3 py-2 text-xs font-medium tabular-nums ${r.score >= 0.5 ? 'text-sev-high' : 'text-muted'}`}
                    >
                      {pct(r.score)}
                    </td>
                    <td className="ltr px-3 py-2 text-xs">
                      <a href={`/assets/${r.subjectId}`} className="hover:underline">
                        {r.subjectType} {r.subjectId.slice(0, 8)}
                      </a>
                    </td>
                    <td className="ltr px-3 py-2 text-[11px] text-muted">
                      {r.features
                        .map(
                          (f) =>
                            `${f.feature}=${f.current} (median ${f.median}, z ${f.z.toFixed(1)})`,
                        )
                        .join(' · ')}
                    </td>
                    <td className="ltr px-3 py-2 text-[11px] text-muted">
                      {r.modelName}@{r.modelVersion} · {r.featureSetVersion}
                    </td>
                    <td className="px-3 py-2 text-[11px] text-muted">
                      {when.format(new Date(r.createdAt))}
                    </td>
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
