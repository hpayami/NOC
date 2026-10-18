import Link from 'next/link';
import { PlatformConditions, PlatformStatus, type CapabilityState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { CapabilityBadge } from '@/components/status-badges';
import { ConditionsPanel } from '@/components/conditions-panel';
import type { MessageKey } from '@/i18n/messages';

export const dynamic = 'force-dynamic';

const CAP_LABEL: Record<CapabilityState, MessageKey> = {
  available: 'cap.available',
  degraded: 'cap.degraded',
  disabled: 'cap.disabled',
  not_configured: 'cap.not_configured',
  not_implemented: 'cap.not_implemented',
};

export default async function CommandCenter() {
  const { t, locale } = await getI18n();
  const [status, conditions, me] = await Promise.all([
    apiFetch('/api/v1/platform/status', PlatformStatus),
    apiFetch('/api/v1/operations/conditions', PlatformConditions),
    getSessionUser(),
  ]);
  const canManage = (me?.permissions ?? []).includes('notifications.manage');
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  });

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('cc.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('cc.subtitle')}</p>
        <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
          <div>
            <dt className="inline">{t('cc.db')}: </dt>
            <dd
              className={`ltr inline ${status.database.state === 'available' ? 'text-ok' : 'text-sev-critical'}`}
            >
              {status.database.state}
            </dd>
          </div>
          <div>
            <dt className="inline">{t('cc.migrations')}: </dt>
            <dd className="inline">{fmt.format(status.database.migrationsApplied)}</dd>
          </div>
          <div>
            <dd className="inline">{t('cc.no_demo')}</dd>
          </div>
          <div>
            <dt className="inline">{t('cc.generated')}: </dt>
            <dd className="inline">{when.format(new Date(status.generatedAt))}</dd>
          </div>
        </dl>
      </header>

      <section aria-labelledby="conditions">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 id="conditions" className="text-lg font-medium">
            {t('cc.conditions')}
          </h2>
          <Link href="/operations" className="text-xs text-muted underline">
            {canManage ? t('cc.operations_link') : t('ops.title')}
          </Link>
        </div>
        <ConditionsPanel
          data={conditions}
          labels={{
            none: t('cc.conditions_none'),
            checks: t('cc.checks'),
            ok: t('cc.checks_ok'),
            failing: t('cc.checks_failing'),
            unavailable: t('cc.checks_unavailable'),
            open: t('cond.open'),
            severity: {
              critical: t('cond.critical'),
              warning: t('cond.warning'),
              info: t('cond.info'),
            },
          }}
        />
      </section>

      <section aria-labelledby="metrics">
        <h2 id="metrics" className="mb-3 text-lg font-medium">
          {t('cc.metrics')}
        </h2>
        <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
          {status.metrics.map((m) => (
            <li key={m.id} className="rounded-lg border border-border bg-surface p-4">
              <p className="ltr text-xs text-muted">{m.id}</p>
              <p className="mt-2 text-3xl font-semibold tabular-nums">
                {m.value === null ? (
                  <span className="text-muted">{t('metric.na')}</span>
                ) : (
                  fmt.format(m.value)
                )}
              </p>
              <p className="mt-2 text-xs">
                <span
                  className={
                    m.sourceState === 'available'
                      ? 'text-ok'
                      : m.sourceState === 'unreachable'
                        ? 'text-sev-critical'
                        : 'text-sev-low'
                  }
                >
                  {t(`metric.${m.sourceState}` as MessageKey)}
                </span>
                <span className="text-muted"> · </span>
                <span className="ltr text-muted">{m.source}</span>
              </p>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="caps">
        <h2 id="caps" className="mb-3 text-lg font-medium">
          {t('cc.capabilities')}
        </h2>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-start text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">ID</th>
                <th className="px-3 py-2 text-start">{t('cap.phase')}</th>
                <th className="px-3 py-2 text-start">{t('admin.status')}</th>
                <th className="px-3 py-2 text-start">—</th>
              </tr>
            </thead>
            <tbody>
              {status.capabilities.map((c) => (
                <tr key={c.id} className="border-t border-border">
                  <td className="ltr px-3 py-2 text-xs">{c.id}</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.format(c.phase)}</td>
                  <td className="px-3 py-2">
                    <CapabilityBadge state={c.state} label={t(CAP_LABEL[c.state])} />
                  </td>
                  <td className="px-3 py-2 text-xs text-muted">{c.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="assurance">
        <h2 id="assurance" className="mb-2 text-lg font-medium">
          {t('cc.assurance')}
        </h2>
        <ul className="flex flex-wrap gap-2">
          {status.assuranceStates.map((s) => (
            <li
              key={s}
              className="ltr rounded border border-border bg-surface px-2 py-1 text-xs text-muted"
            >
              {s}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
