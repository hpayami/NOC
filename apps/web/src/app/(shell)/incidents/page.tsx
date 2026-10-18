import { z } from 'zod';
import { IncidentStats, IncidentSummary, Site } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { SEV_STYLE, STATUS_LABEL } from './labels';
import { NewIncidentForm } from './new-incident-form';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(IncidentSummary), nextCursor: z.string().nullable() });
const Sites = z.object({ items: z.array(Site), restricted: z.boolean() });

export default async function IncidentsPage({
  searchParams,
}: {
  searchParams: Promise<{ all?: string; cursor?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { all, cursor } = await searchParams;
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('incidents.manage') ?? false;
  const qs = new URLSearchParams({
    limit: '50',
    ...(all ? {} : { open: 'true' }),
    ...(cursor ? { cursor } : {}),
  });
  const [stats, page, sites] = await Promise.all([
    apiFetch('/api/v1/incidents/stats', IncidentStats),
    apiFetch(`/api/v1/incidents?${qs}`, Page),
    canManage
      ? apiFetch('/api/v1/sites', Sites)
      : Promise.resolve({ items: [], restricted: false }),
  ]);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const tiles: Array<[string, string]> = [
    [t('inc.total'), fmt.format(stats.total)],
    [t('inc.open'), fmt.format(stats.open)],
    [t('inc.closed_30d'), fmt.format(stats.closedLast30Days)],
    [
      t('inc.mttc'),
      stats.meanTimeToCloseSeconds === null
        ? '—'
        : `${fmt.format(Math.round(stats.meanTimeToCloseSeconds / 360) / 10)} h`,
    ],
  ];

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('inc.title')}</h1>
          <p className="mt-1 text-sm text-muted">{t('inc.subtitle')}</p>
        </div>
        <a
          href={all ? '/incidents' : '/incidents?all=1'}
          className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {all ? t('alerts.show_open') : t('alerts.show_all')}
        </a>
      </header>

      <ul className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map(([label, value]) => (
          <li key={label} className="rounded-lg border border-border bg-surface p-4">
            <p className="text-xs text-muted">{label}</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">{value}</p>
          </li>
        ))}
      </ul>

      {canManage ? (
        <NewIncidentForm
          labels={{
            heading: t('inc.new'),
            title: t('inc.new_title'),
            type: t('inc.type'),
            severity: t('alerts.severity'),
            summary: t('inc.summary'),
            submit: t('inc.create'),
            site: t('inc.site'),
            siteAuto: t('inc.site_auto'),
            types: {
              security: t('inc.type.security'),
              noc_outage: t('inc.type.noc_outage'),
              policy_violation: t('inc.type.policy_violation'),
            },
          }}
          sites={sites.items.map((s) => ({ key: s.key, name: s.name }))}
          restricted={sites.restricted}
        />
      ) : null}

      {page.items.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface p-5 text-sm">
          <p>{t('inc.empty')}</p>
          <p className="mt-1 text-xs text-muted">{t('inc.empty_hint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">{t('alerts.severity')}</th>
                <th className="px-3 py-2 text-start">{t('inc.incident')}</th>
                <th className="px-3 py-2 text-start">{t('inc.status')}</th>
                <th className="px-3 py-2 text-start">{t('inc.alerts')}</th>
                <th className="px-3 py-2 text-start">{t('inc.opened')}</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((i) => (
                <tr key={i.id} className="border-t border-border align-top">
                  <td className={`ltr px-3 py-2 text-xs font-medium ${SEV_STYLE[i.severity]}`}>
                    {i.severity}
                  </td>
                  <td className="px-3 py-2">
                    <a href={`/incidents/${i.id}`} className="block hover:underline">
                      {i.title}
                    </a>
                    <span className="ltr block text-[10px] text-muted">
                      {t(`inc.type.${i.type}` as MessageKey)} · {i.site ?? '—'} · {i.id.slice(0, 8)}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs">{t(STATUS_LABEL[i.status])}</td>
                  <td className="ltr px-3 py-2 text-xs tabular-nums">{fmt.format(i.alertCount)}</td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {when.format(new Date(i.openedAt))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page.nextCursor ? (
        <a
          href={`/incidents?${all ? 'all=1&' : ''}cursor=${encodeURIComponent(page.nextCursor)}`}
          className="inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {t('audit.next')} →
        </a>
      ) : null}
    </div>
  );
}
