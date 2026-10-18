import { z } from 'zod';
import { EngagementRecord, PlatformStatus } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { CapabilityBadge } from '@/components/status-badges';
import type { MessageKey } from '@/i18n/messages';
import { NewEngagementForm } from './controls';
import { ENG_STATUS_LABEL, ENG_STATUS_STYLE } from './labels';

export const dynamic = 'force-dynamic';
const List = z.object({ items: z.array(EngagementRecord) });
const CAP_LABEL: Record<string, MessageKey> = {
  available: 'cap.available',
  degraded: 'cap.degraded',
  disabled: 'cap.disabled',
  not_configured: 'cap.not_configured',
  not_implemented: 'cap.not_implemented',
};

export default async function RedTeamPage() {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const perms = new Set(me?.permissions ?? []);
  const [list, status] = await Promise.all([
    apiFetch('/api/v1/assessments/engagements?limit=100', List),
    apiFetch('/api/v1/platform/status', PlatformStatus),
  ]);
  const caps = status.capabilities.filter((c) => c.id.startsWith('assessment.'));
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('eng.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('eng.subtitle')}</p>
      </header>

      <ul className="space-y-2 rounded-lg border border-border bg-surface p-4">
        {caps.map((c) => (
          <li key={c.id} className="flex flex-wrap items-center gap-3 text-sm">
            <span className="ltr text-xs">{c.id}</span>
            <CapabilityBadge
              state={c.state}
              label={t(CAP_LABEL[c.state] ?? 'cap.not_implemented')}
            />
            <span className="text-xs text-muted">{c.reason}</span>
          </li>
        ))}
      </ul>

      <section className="space-y-3" aria-labelledby="engagements">
        <h2 id="engagements" className="font-medium">
          {t('eng.list')}
        </h2>
        {list.items.length === 0 ? (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm">
            <p>{t('eng.empty')}</p>
            <p className="mt-1 text-xs text-muted">{t('eng.empty_hint')}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('eng.reference')}</th>
                  <th className="px-3 py-2 text-start">{t('eng.status')}</th>
                  <th className="px-3 py-2 text-start">{t('eng.scope')}</th>
                  <th className="px-3 py-2 text-start">{t('eng.window')}</th>
                  <th className="px-3 py-2 text-start">{t('eng.runs')}</th>
                  <th className="px-3 py-2 text-start">{t('eng.findings')}</th>
                </tr>
              </thead>
              <tbody>
                {list.items.map((e) => (
                  <tr key={e.id} className="border-t border-border align-top">
                    <td className="px-3 py-2">
                      <a href={`/red-team/${e.id}`} className="ltr block hover:underline">
                        {e.reference}
                      </a>
                      <span className="block text-[10px] text-muted">
                        {e.authorizingOrganization} · {e.authorizationReference}
                      </span>
                    </td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${ENG_STATUS_STYLE[e.status]}`}
                      data-testid="eng-status"
                    >
                      {t(ENG_STATUS_LABEL[e.status])}
                      {e.approvedScopeVersion !== e.scopeVersion ? (
                        <span className="block text-[10px] text-sev-medium">
                          v{e.scopeVersion} {t('eng.unapproved_scope')}
                        </span>
                      ) : null}
                    </td>
                    <td className="ltr px-3 py-2 text-[11px] text-muted">
                      {[...e.scope.includeCidrs, ...e.scope.includeAddresses].join(', ')}
                    </td>
                    <td className="px-3 py-2 text-[11px] text-muted">
                      {when.format(new Date(e.scope.windowStart))} →{' '}
                      {when.format(new Date(e.scope.windowEnd))}
                    </td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">{fmt.format(e.runCount)}</td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">
                      {fmt.format(e.findingCount)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {perms.has('assessments.plan') ? (
        <NewEngagementForm
          labels={{
            heading: t('eng.new'),
            reference: t('eng.reference'),
            org: t('eng.org'),
            authRef: t('eng.auth_ref'),
            objective: t('eng.objective'),
            includeCidrs: t('eng.include_cidrs'),
            includeAddresses: t('eng.include_addresses'),
            excludeCidrs: t('eng.exclude_cidrs'),
            techniques: t('eng.techniques'),
            windowStart: t('eng.window_start'),
            windowEnd: t('eng.window_end'),
            stopConditions: t('eng.stop_conditions'),
            emergencyContact: t('eng.emergency_contact'),
            submit: t('eng.create'),
          }}
        />
      ) : null}
    </div>
  );
}
