import { z } from 'zod';
import {
  DetectionRuleDetail,
  RuleDeploymentState,
  RuleStats,
  type RuleLifecycle,
} from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { ImportRulesForm } from './import-form';
import { DeployButton, TargetsForm } from './rule-controls';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(DetectionRuleDetail), nextCursor: z.string().nullable() });
const Deployment = z.object({ items: z.array(RuleDeploymentState) });
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
  const canDeploy = me?.permissions.includes('detection_rules.deploy') ?? false;
  const qs = new URLSearchParams({
    limit: '50',
    ...(cursor ? { cursor } : {}),
    ...(q ? { q } : {}),
  });
  const [stats, page, deployment] = await Promise.all([
    apiFetch('/api/v1/detection-rules/stats', RuleStats),
    apiFetch(`/api/v1/detection-rules?${qs}`, Page),
    apiFetch('/api/v1/detection-rules/deployment', Deployment),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
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

      <section className="space-y-2" aria-labelledby="deployment">
        <h2 id="deployment" className="font-medium">
          {t('rules.deployment')}
        </h2>
        <p className="text-xs text-muted">{t('rules.deployment_hint')}</p>
        {deployment.items.length === 0 ? (
          <p className="text-sm text-muted">{t('rules.no_sensors')}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('sensors.name')}</th>
                  <th className="px-3 py-2 text-start">{t('sensors.kind')}</th>
                  <th className="px-3 py-2 text-start">{t('sensors.site')}</th>
                  <th className="px-3 py-2 text-start">{t('rules.expected_rules')}</th>
                  <th className="px-3 py-2 text-start">{t('rules.deployment')}</th>
                </tr>
              </thead>
              <tbody>
                {deployment.items.map((d) => (
                  <tr
                    key={d.sensorId}
                    className="border-t border-border"
                    data-testid="rule-deployment-row"
                  >
                    <td className="ltr px-3 py-2 text-xs">{d.sensorName}</td>
                    <td className="ltr px-3 py-2 text-xs">{d.kind}</td>
                    <td className="ltr px-3 py-2 text-xs">{d.site ?? '—'}</td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">
                      {d.engine ? d.expectedRuleCount : '—'}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {!d.engine ? (
                        <span className="text-muted">{t('rules.no_bundle')}</span>
                      ) : d.inSync ? (
                        <span className="text-ok">{t('rules.in_sync')}</span>
                      ) : (
                        <span className="text-sev-medium">{t('rules.out_of_sync')}</span>
                      )}
                      <span className="ltr block text-[10px] text-muted">
                        {d.appliedBundleSha256 ? d.appliedBundleSha256.slice(0, 12) : '—'}
                        {d.appliedAt ? ` · ${when.format(new Date(d.appliedAt))}` : ''}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

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
                      {canDeploy && r.lifecycle === 'validated' ? (
                        <div className="mt-1">
                          <DeployButton id={r.id} label={t('rules.deploy')} />
                        </div>
                      ) : null}
                      <span className="block text-[10px] text-muted">
                        {t('rules.targets')}: {r.sites.join(', ') || '*'}
                      </span>
                      {canChange ? (
                        <TargetsForm
                          id={r.id}
                          sites={r.sites}
                          labels={{
                            placeholder: t('rules.targets_hint'),
                            save: t('rules.save_targets'),
                          }}
                        />
                      ) : null}
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
