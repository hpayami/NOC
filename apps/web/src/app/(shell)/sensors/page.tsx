import { z } from 'zod';
import { SensorStatus, type SensorHealthState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { EnrolmentTokenButton } from './enrolment-button';

export const dynamic = 'force-dynamic';

const STYLE: Record<SensorHealthState, string> = {
  healthy: 'text-ok',
  degraded: 'text-sev-medium',
  unhealthy: 'text-sev-critical',
  silent: 'text-sev-high',
  unknown: 'text-muted',
};

export default async function SensorsPage() {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('sensors.manage') ?? false;
  const sensors = await apiFetch('/api/v1/sensors', z.array(SensorStatus));
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{t('sensors.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('sensors.subtitle')}</p>
      </header>
      {sensors.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface p-5 text-sm">
          <p>{t('sensors.empty')}</p>
          <p className="mt-1 text-xs text-muted">{t('sensors.empty_hint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-start">{t('sensors.name')}</th>
                <th className="px-3 py-2 text-start">{t('sensors.kind')}</th>
                <th className="px-3 py-2 text-start">{t('sensors.mode')}</th>
                <th className="px-3 py-2 text-start">{t('sensors.state')}</th>
                <th className="px-3 py-2 text-start">{t('sensors.heartbeat')}</th>
                <th className="px-3 py-2 text-start">{t('sensors.host')}</th>
                {canManage ? <th className="px-3 py-2 text-start">{t('common.actions')}</th> : null}
              </tr>
            </thead>
            <tbody>
              {sensors.map(({ sensor, derivedState, heartbeatAgeSeconds }) => (
                <tr key={sensor.id} className="border-t border-border align-top">
                  <td className="px-3 py-2">
                    <span className="font-medium">{sensor.name}</span>
                    <span className="ltr block text-[10px] text-muted">{sensor.id}</span>
                  </td>
                  <td className="ltr px-3 py-2 text-xs">{sensor.kind}</td>
                  <td className="ltr px-3 py-2 text-xs">{sensor.mode}</td>
                  <td className={`ltr px-3 py-2 text-xs ${STYLE[derivedState]}`}>{derivedState}</td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {sensor.lastHeartbeatAt
                      ? `${when.format(new Date(sensor.lastHeartbeatAt))} (${Math.round(heartbeatAgeSeconds ?? 0)}s)`
                      : t('sensors.never')}
                  </td>
                  <td className="ltr px-3 py-2 text-xs text-muted">
                    {sensor.hostAssetId ? sensor.hostAssetId.slice(0, 8) : '—'}
                  </td>
                  {canManage ? (
                    <td className="px-3 py-2">
                      <EnrolmentTokenButton
                        sensorId={sensor.id}
                        labels={{
                          issue: t('sensors.issue_token'),
                          shownOnce: t('sensors.token_once'),
                          expires: t('sensors.token_expires'),
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
    </div>
  );
}
