import { z } from 'zod';
import { FindingRecord, FindingStatusValues, type Severity } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { FindingForm } from '../red-team/controls';

export const dynamic = 'force-dynamic';
const List = z.object({ items: z.array(FindingRecord) });
const SEV: Record<Severity, string> = {
  info: 'text-sev-info',
  low: 'text-sev-low',
  medium: 'text-sev-medium',
  high: 'text-sev-high',
  critical: 'text-sev-critical',
};

export default async function VulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<{ all?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { all } = await searchParams;
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('findings.manage') ?? false;
  const list = await apiFetch(`/api/v1/findings?limit=200${all ? '' : '&status=open'}`, List);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('vuln.title')}</h1>
          <p className="mt-1 text-sm text-muted">{t('vuln.subtitle')}</p>
        </div>
        <a
          href={all ? '/vulnerabilities' : '/vulnerabilities?all=1'}
          className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {all ? t('alerts.show_open') : t('alerts.show_all')}
        </a>
      </header>
      {list.items.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface p-5 text-sm">
          <p>{t('vuln.empty')}</p>
          <p className="mt-1 text-xs text-muted">{t('vuln.empty_hint')}</p>
        </div>
      ) : (
        <ul className="space-y-2">
          {list.items.map((f) => (
            <li key={f.id} className="rounded-lg border border-border bg-surface px-4 py-3 text-sm">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className={`ltr font-medium ${SEV[f.severity]}`}>{f.severity}</span>
                <span className="ltr font-medium">{f.title}</span>
                <span className="ltr">{f.status}</span>
                {f.validated ? (
                  <span className="rounded border border-ok/30 px-1 text-ok">
                    {t('vuln.validated')}
                  </span>
                ) : null}
                <span className="ltr text-muted">{f.cwe.join(', ')}</span>
                <span className="ms-auto text-muted">
                  {t('vuln.last_seen')} {when.format(new Date(f.lastDetectedAt))}
                </span>
              </div>
              <p className="mt-1 text-xs text-muted">{f.description}</p>
              {f.lastNote ? (
                <p className="mt-1 text-xs">
                  {t('vuln.note')}: {f.lastNote}
                </p>
              ) : null}
              {canManage ? (
                <FindingForm
                  id={f.id}
                  statuses={[...FindingStatusValues]}
                  labels={{ note: t('vuln.note'), submit: t('common.save') }}
                />
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
