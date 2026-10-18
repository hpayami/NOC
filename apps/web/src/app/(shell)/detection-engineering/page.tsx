import { z } from 'zod';
import { DetectionRuleDetail, RuleStats, type RuleLifecycle } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { ImportRulesForm } from './import-form';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(DetectionRuleDetail), nextCursor: z.string().nullable() });
const LC_STYLE: Record<RuleLifecycle, string> = {
  draft: 'text-muted',
  validated: 'text-sev-low',
  deployed: 'text-ok',
  disabled: 'text-sev-medium',
  retired: 'text-muted',
};

export default async function DetectionEngineeringPage({
  searchParams,
}: {
  searchParams: Promise<{ cursor?: string; q?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { cursor, q } = await searchParams;
  const me = await getSessionUser();
  const canChange = me?.permissions.includes('detection_rules.change') ?? false;
  const qs = new URLSearchParams({
    limit: '50',
    ...(cursor ? { cursor } : {}),
    ...(q ? { q } : {}),
  });
  const [stats, page] = await Promise.all([
    apiFetch('/api/v1/detection-rules/stats', RuleStats),
    apiFetch(`/api/v1/detection-rules?${qs}`, Page),
  ]);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('rules.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('rules.subtitle')}</p>
      </header>

      <ul className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <li className="rounded-lg border border-border bg-surface p-4">
          <p className="text-xs text-muted">{t('rules.total')}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">{fmt.format(stats.total)}</p>
        </li>
        {(Object.keys(LC_STYLE) as RuleLifecycle[]).map((lc) => (
          <li key={lc} className="rounded-lg border border-border bg-surface p-4">
            <p className={`ltr text-xs ${LC_STYLE[lc]}`}>{lc}</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">
              {fmt.format(stats.byLifecycle[lc])}
            </p>
          </li>
        ))}
        <li className="rounded-lg border border-border bg-surface p-4">
          <p className="text-xs text-muted">{t('rules.with_techniques')}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">
            {fmt.format(stats.withTechniques)}
          </p>
        </li>
      </ul>

      {canChange ? (
        <ImportRulesForm
          labels={{
            title: t('rules.import'),
            source: t('rules.source'),
            ruleSet: t('rules.rule_set'),
            license: t('rules.license'),
            content: t('rules.content'),
            submit: t('rules.import_submit'),
            result: t('rules.import_result'),
          }}
        />
      ) : null}

      <section aria-labelledby="rules">
        <form className="mb-3 flex gap-2" action="/detection-engineering">
          <input
            name="q"
            defaultValue={q ?? ''}
            placeholder={t('rules.search')}
            className="ltr w-64 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm"
          />
          <button
            type="submit"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
          >
            {t('rules.search_go')}
          </button>
        </form>
        {page.items.length === 0 ? (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm">
            <p>{t('rules.empty')}</p>
            <p className="mt-1 text-xs text-muted">{t('rules.empty_hint')}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('rules.rule')}</th>
                  <th className="px-3 py-2 text-start">{t('alerts.severity')}</th>
                  <th className="px-3 py-2 text-start">{t('rules.lifecycle')}</th>
                  <th className="px-3 py-2 text-start">ATT&CK</th>
                  <th className="px-3 py-2 text-start">{t('rules.license')}</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((r) => (
                  <tr key={r.id} className="border-t border-border align-top">
                    <td className="px-3 py-2">
                      <span className="ltr block">{r.name}</span>
                      <span className="ltr block text-[10px] text-muted">
                        {r.source} · {r.externalId} rev {r.revision}
                        {r.enabled ? '' : ` · ${t('rules.disabled_in_set')}`}
                      </span>
                    </td>
                    <td className="ltr px-3 py-2 text-xs">{r.severity}</td>
                    <td className={`ltr px-3 py-2 text-xs ${LC_STYLE[r.lifecycle]}`}>
                      {r.lifecycle}
                    </td>
                    <td className="ltr px-3 py-2 text-xs text-muted">
                      {r.attackTechniques.join(', ') || '—'}
                    </td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{r.license ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {page.nextCursor ? (
          <a
            href={`/detection-engineering?${q ? `q=${encodeURIComponent(q)}&` : ''}cursor=${encodeURIComponent(page.nextCursor)}`}
            className="mt-3 inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
          >
            {t('audit.next')} →
          </a>
        ) : null}
      </section>
    </div>
  );
}
