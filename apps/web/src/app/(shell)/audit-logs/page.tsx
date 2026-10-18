import Link from 'next/link';
import { z } from 'zod';
import { AuditEvent } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { OutcomeBadge } from '@/components/status-badges';
import { VerifyChainButton } from './verify-button';

export const dynamic = 'force-dynamic';
const Page = z.object({ items: z.array(AuditEvent), nextCursor: z.string().nullable() });

export default async function AuditLogsPage({
  searchParams,
}: {
  searchParams: Promise<{ cursor?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { cursor } = await searchParams;
  const me = await getSessionUser();
  const canVerify = me?.permissions.includes('audit.verify') ?? false;
  const qs = new URLSearchParams({
    limit: '50',
    ...(cursor && /^\d+$/.test(cursor) ? { cursor } : {}),
  });
  const page = await apiFetch(`/api/v1/audit?${qs}`, Page);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('audit.title')}</h1>
          <p className="mt-1 text-sm text-muted">{t('audit.subtitle')}</p>
        </div>
        {canVerify ? (
          <VerifyChainButton
            labels={{
              verify: t('audit.verify'),
              valid: t('audit.valid'),
              invalid: t('audit.invalid'),
              checked: t('audit.checked'),
            }}
          />
        ) : null}
      </header>
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead className="bg-surface text-xs text-muted">
            <tr>
              <th className="px-3 py-2 text-start">{t('audit.seq')}</th>
              <th className="px-3 py-2 text-start">{t('audit.time')}</th>
              <th className="px-3 py-2 text-start">{t('audit.actor')}</th>
              <th className="px-3 py-2 text-start">{t('audit.action')}</th>
              <th className="px-3 py-2 text-start">{t('audit.outcome')}</th>
              <th className="px-3 py-2 text-start">{t('audit.target')}</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((e) => (
              <tr key={e.seq} className="border-t border-border align-top">
                <td className="ltr px-3 py-2 text-xs tabular-nums text-muted">{e.seq}</td>
                <td className="px-3 py-2 text-xs">{when.format(new Date(e.occurredAt))}</td>
                <td className="ltr px-3 py-2 text-xs">{e.actorLabel}</td>
                <td className="ltr px-3 py-2 text-xs">{e.action}</td>
                <td className="px-3 py-2">
                  <OutcomeBadge outcome={e.outcome} />
                </td>
                <td className="ltr px-3 py-2 text-xs text-muted">
                  {e.targetType ? `${e.targetType}:${e.targetId ?? ''}` : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {page.nextCursor ? (
        <Link
          href={`/audit-logs?cursor=${page.nextCursor}`}
          className="inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {t('audit.next')} →
        </Link>
      ) : null}
    </div>
  );
}
