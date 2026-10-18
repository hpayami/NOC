import { notFound } from 'next/navigation';
import { PlatformStatus, type CapabilityState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { NAV, navBySlug } from '@/lib/nav';
import { CapabilityBadge } from '@/components/status-badges';
import type { MessageKey } from '@/i18n/messages';

export const dynamic = 'force-dynamic';
export const dynamicParams = false;
export function generateStaticParams() {
  return NAV.filter((n) => !n.implemented).map((n) => ({ section: n.slug }));
}

const CAP_LABEL: Record<CapabilityState, MessageKey> = {
  available: 'cap.available',
  degraded: 'cap.degraded',
  disabled: 'cap.disabled',
  not_configured: 'cap.not_configured',
  not_implemented: 'cap.not_implemented',
};

/**
 * Honest placeholder for workspaces whose plane is not built yet: it shows the real capability
 * state from the API and the phase in which the workspace is planned — never sample data.
 */
export default async function SectionPage({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  const item = navBySlug(section);
  if (!item || item.implemented) notFound();
  const { t, locale } = await getI18n();
  const status = await apiFetch('/api/v1/platform/status', PlatformStatus);
  const caps = status.capabilities.filter((c) => item.capabilities.includes(c.id));
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');

  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{t(item.label)}</h1>
        <p className="mt-1 text-sm text-muted">
          {t('section.planned_phase')} {fmt.format(item.phase)}
        </p>
      </header>
      <div className="rounded-lg border border-border bg-surface p-5">
        <h2 className="font-medium">{t('section.not_ready.title')}</h2>
        <p className="mt-1 text-sm text-muted">{t('section.not_ready.body')}</p>
        <ul className="mt-4 space-y-2">
          {caps.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-3 text-sm">
              <span className="ltr text-xs">{c.id}</span>
              <CapabilityBadge state={c.state} label={t(CAP_LABEL[c.state])} />
              <span className="text-xs text-muted">{c.reason}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
