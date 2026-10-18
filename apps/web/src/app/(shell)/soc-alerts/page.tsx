import { z } from 'zod';
import { Alert, type AlertStatus, type Severity } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { LiveRefresh } from '@/components/live-refresh';
import { TriageButtons } from './triage-buttons';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(Alert), nextCursor: z.string().nullable() });

const SEV_STYLE: Record<Severity, string> = {
  info: 'text-sev-info',
  low: 'text-sev-low',
  medium: 'text-sev-medium',
  high: 'text-sev-high',
  critical: 'text-sev-critical',
};
const STATUS_LABEL: Record<AlertStatus, MessageKey> = {
  new: 'alert.status.new',
  acknowledged: 'alert.status.acknowledged',
  investigating: 'alert.status.investigating',
  escalated: 'alert.status.escalated',
  suppressed: 'alert.status.suppressed',
  false_positive: 'alert.status.false_positive',
  resolved: 'alert.status.resolved',
};

export default async function SocAlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ all?: string; cursor?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { all, cursor } = await searchParams;
  const me = await getSessionUser();
  const canTriage = me?.permissions.includes('alerts.triage') ?? false;
  const qs = new URLSearchParams({
    limit: '50',
    ...(all ? {} : { open: 'true' }),
    ...(cursor ? { cursor } : {}),
  });
  const page = await apiFetch(`/api/v1/alerts?${qs}`, Page);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('alerts.title')}</h1>
          <p className="mt-1 text-sm text-muted">{t('alerts.subtitle')}</p>
          <div className="mt-2">
            <LiveRefresh labels={{ live: t('alerts.live'), offline: t('alerts.offline') }} />
          </div>
        </div>
        <a
          href={all ? '/soc-alerts' : '/soc-alerts?all=1'}
          className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {all ? t('alerts.show_open') : t('alerts.show_all')}
        </a>
      </header>
      {page.items.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface p-5 text-sm">
          <p>{t('alerts.empty')}</p>
          <p className="mt-1 text-xs text-muted">{t('alerts.empty_hint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">{t('alerts.priority')}</th>
                <th className="px-3 py-2 text-start">{t('alerts.severity')}</th>
                <th className="px-3 py-2 text-start">{t('alerts.alert')}</th>
                <th className="px-3 py-2 text-start">{t('alerts.count')}</th>
                <th className="px-3 py-2 text-start">{t('alerts.last_seen')}</th>
                <th className="px-3 py-2 text-start">{t('admin.status')}</th>
                {canTriage ? <th className="px-3 py-2 text-start">{t('common.actions')}</th> : null}
              </tr>
            </thead>
            <tbody>
              {page.items.map((a) => (
                <tr key={a.id} className="border-t border-border align-top">
                  <td className="ltr px-3 py-2 text-xs tabular-nums">
                    {Math.round(a.priorityScore)}
                  </td>
                  <td className={`ltr px-3 py-2 text-xs font-medium ${SEV_STYLE[a.severity]}`}>
                    {a.severity}
                  </td>
                  <td className="px-3 py-2">
                    <span className="ltr block">{a.title}</span>
                    <span className="ltr block text-[10px] text-muted">
                      {a.sourceProduct} · {a.confidence} ·{' '}
                      {a.assetId ? `asset ${a.assetId.slice(0, 8)}` : t('alerts.no_asset')}
                    </span>
                  </td>
                  <td className="ltr px-3 py-2 text-xs tabular-nums">
                    {fmt.format(a.occurrenceCount)}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {when.format(new Date(a.lastSeenAt))}
                  </td>
                  <td className="px-3 py-2 text-xs">{t(STATUS_LABEL[a.status])}</td>
                  {canTriage ? (
                    <td className="px-3 py-2">
                      <TriageButtons
                        alertId={a.id}
                        status={a.status}
                        labels={{
                          acknowledge: t('alerts.act.acknowledge'),
                          investigate: t('alerts.act.investigate'),
                          resolve: t('alerts.act.resolve'),
                          false_positive: t('alerts.act.false_positive'),
                          reopen: t('alerts.act.reopen'),
                          note: t('alerts.note'),
                        }}
                      />
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page.nextCursor ? (
        <a
          href={`/soc-alerts?${all ? 'all=1&' : ''}cursor=${encodeURIComponent(page.nextCursor)}`}
          className="inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {t('audit.next')} →
        </a>
      ) : null}
    </div>
  );
}
