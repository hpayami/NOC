import { z } from 'zod';
import { NotificationChannel, NotificationDelivery, PlatformConditions } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { ApiError, apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { ConditionsPanel } from '@/components/conditions-panel';
import { CreateChannelForm } from './channel-form';
import { ChannelControls } from './channel-controls';

export const dynamic = 'force-dynamic';

const Channels = z.object({ items: z.array(NotificationChannel) });
const Deliveries = z.object({ items: z.array(NotificationDelivery) });

export default async function OperationsPage() {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const canManage = (me?.permissions ?? []).includes('notifications.manage');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const conditions = await apiFetch('/api/v1/operations/conditions', PlatformConditions);
  let channels: z.infer<typeof Channels> | null = null;
  let deliveries: z.infer<typeof Deliveries> | null = null;
  if (canManage) {
    try {
      [channels, deliveries] = await Promise.all([
        apiFetch('/api/v1/operations/channels', Channels),
        apiFetch('/api/v1/operations/deliveries', Deliveries),
      ]);
    } catch (e) {
      // The server is the authority; a 403 here means the cookie lags a role change.
      if (!(e instanceof ApiError && e.status === 403)) throw e;
    }
  }
  const severity = {
    critical: t('cond.critical'),
    warning: t('cond.warning'),
    info: t('cond.info'),
  } as const;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('ops.title')}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">{t('ops.subtitle')}</p>
        <p className="mt-2 text-xs text-muted">
          {t('ops.evaluated')}: {when.format(new Date(conditions.evaluatedAt))}
        </p>
      </header>

      <section aria-labelledby="conditions">
        <h2 id="conditions" className="mb-3 text-lg font-medium">
          {t('cc.conditions')}
        </h2>
        <ConditionsPanel
          data={conditions}
          labels={{
            none: t('cc.conditions_none'),
            checks: t('cc.checks'),
            ok: t('cc.checks_ok'),
            failing: t('cc.checks_failing'),
            unavailable: t('cc.checks_unavailable'),
            open: t('cond.open'),
            severity,
          }}
        />
      </section>

      <section aria-labelledby="channels" className="space-y-4">
        <h2 id="channels" className="text-lg font-medium">
          {t('ops.channels')}
        </h2>
        {!canManage || !channels ? (
          <p className="rounded-md border border-border bg-surface p-4 text-sm text-muted">
            {t('ops.forbidden')}
          </p>
        ) : (
          <>
            {channels.items.length === 0 ? (
              <p className="rounded-md border border-border bg-surface p-4 text-sm text-muted">
                {t('ops.no_channels')}
              </p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-sm">
                  <thead className="bg-surface text-xs text-muted">
                    <tr>
                      <th className="px-3 py-2 text-start">{t('ops.name')}</th>
                      <th className="px-3 py-2 text-start">{t('ops.url')}</th>
                      <th className="px-3 py-2 text-start">{t('ops.min_severity')}</th>
                      <th className="px-3 py-2 text-start">{t('admin.status')}</th>
                      <th className="px-3 py-2 text-start">{t('ops.last_attempt')}</th>
                      <th className="px-3 py-2 text-start">—</th>
                    </tr>
                  </thead>
                  <tbody>
                    {channels.items.map((c) => (
                      <tr key={c.id} className="border-t border-border align-top">
                        <td className="px-3 py-2">{c.name}</td>
                        <td className="ltr max-w-xs truncate px-3 py-2 text-xs text-muted">
                          {c.url}
                        </td>
                        <td className="px-3 py-2">{severity[c.minSeverity]}</td>
                        <td className="px-3 py-2">
                          <span className={c.enabled ? 'text-ok' : 'text-muted'}>
                            {c.enabled ? t('ops.enabled') : t('ops.disabled')}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-xs">
                          {c.lastAttemptAt ? (
                            <>
                              <span
                                className={
                                  c.lastStatus === 'sent' ? 'text-ok' : 'text-sev-critical'
                                }
                              >
                                {c.lastStatus === 'sent' ? t('ops.sent') : t('ops.failed')}
                              </span>
                              <span className="text-muted">
                                {' '}
                                · {when.format(new Date(c.lastAttemptAt))}
                              </span>
                              {c.lastError ? (
                                <span className="ltr block text-muted">{c.lastError}</span>
                              ) : null}
                            </>
                          ) : (
                            <span className="text-muted">{t('ops.never')}</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <ChannelControls
                            id={c.id}
                            enabled={c.enabled}
                            labels={{
                              test: t('ops.test'),
                              enable: t('ops.enable'),
                              disable: t('ops.disable'),
                              sent: t('ops.sent'),
                              failed: t('ops.failed'),
                            }}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <CreateChannelForm
              labels={{
                heading: t('ops.create'),
                hint: t('ops.create_hint'),
                name: t('ops.name'),
                url: t('ops.url'),
                secret: t('ops.secret'),
                minSeverity: t('ops.min_severity'),
                submit: t('ops.create_submit'),
                created: t('ops.created'),
                severity,
              }}
            />
            <section aria-labelledby="deliveries">
              <h3 id="deliveries" className="mb-2 font-medium">
                {t('ops.deliveries')}
              </h3>
              {!deliveries || deliveries.items.length === 0 ? (
                <p className="text-sm text-muted">{t('ops.no_deliveries')}</p>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full text-sm">
                    <thead className="bg-surface text-xs text-muted">
                      <tr>
                        <th className="px-3 py-2 text-start">{t('ops.attempted')}</th>
                        <th className="px-3 py-2 text-start">{t('ops.event')}</th>
                        <th className="px-3 py-2 text-start">{t('ops.condition')}</th>
                        <th className="px-3 py-2 text-start">{t('admin.status')}</th>
                        <th className="px-3 py-2 text-start">HTTP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deliveries.items.map((d) => (
                        <tr key={d.id} className="border-t border-border">
                          <td className="px-3 py-2 text-xs">
                            {when.format(new Date(d.attemptedAt))}
                          </td>
                          <td className="ltr px-3 py-2 text-xs">{d.event}</td>
                          <td className="ltr px-3 py-2 text-xs">{d.conditionId}</td>
                          <td className="px-3 py-2 text-xs">
                            <span className={d.status === 'sent' ? 'text-ok' : 'text-sev-critical'}>
                              {d.status === 'sent' ? t('ops.sent') : t('ops.failed')}
                            </span>
                            {d.error ? <span className="ltr text-muted"> {d.error}</span> : null}
                          </td>
                          <td className="ltr px-3 py-2 text-xs tabular-nums">
                            {d.httpStatus ?? '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}
      </section>
    </div>
  );
}
