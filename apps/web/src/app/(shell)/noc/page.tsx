import { MonitoringOverview, type OperationalStatus, type SensorHealthState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';

export const dynamic = 'force-dynamic';

const STATUS_LABEL: Record<OperationalStatus, MessageKey> = {
  online: 'status.online',
  offline: 'status.offline',
  degraded: 'status.degraded',
  unreachable_monitoring_path: 'status.unreachable_monitoring_path',
  maintenance: 'status.maintenance',
  unknown: 'status.unknown',
};
const STATUS_STYLE: Record<OperationalStatus, string> = {
  online: 'text-ok',
  offline: 'text-sev-critical',
  degraded: 'text-sev-medium',
  unreachable_monitoring_path: 'text-sev-high',
  maintenance: 'text-sev-low',
  unknown: 'text-muted',
};
const SENSOR_STYLE: Record<SensorHealthState, string> = {
  healthy: 'text-ok',
  degraded: 'text-sev-medium',
  unhealthy: 'text-sev-critical',
  silent: 'text-sev-high',
  unknown: 'text-muted',
};

export default async function NocPage() {
  const { t, locale } = await getI18n();
  const ov = await apiFetch('/api/v1/monitoring/overview', MonitoringOverview);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const statuses = Object.keys(STATUS_LABEL) as OperationalStatus[];

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('noc.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('noc.subtitle')}</p>
      </header>

      <section aria-labelledby="status">
        <h2 id="status" className="mb-3 text-lg font-medium">
          {t('noc.asset_status')}
        </h2>
        <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {statuses.map((s) => (
            <li key={s} className="rounded-lg border border-border bg-surface p-4">
              <p className={`text-xs ${STATUS_STYLE[s]}`}>{t(STATUS_LABEL[s])}</p>
              <p className="mt-1 text-3xl font-semibold tabular-nums">
                {fmt.format(ov.assetsByStatus[s])}
              </p>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-muted">
          {t('noc.checks')}: {fmt.format(ov.checks.enabled)}/{fmt.format(ov.checks.total)} ·{' '}
          {t('noc.platform_run')}: {fmt.format(ov.checks.platformRun)}
        </p>
      </section>

      <section aria-labelledby="sensors">
        <h2 id="sensors" className="mb-3 text-lg font-medium">
          {t('noc.sensors')}
        </h2>
        {ov.sensors.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            {t('noc.no_sensors')}
          </p>
        ) : (
          <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {ov.sensors.map(({ sensor, derivedState, heartbeatAgeSeconds, latest }) => (
              <li
                key={sensor.id}
                className="rounded-lg border border-border bg-surface p-4 text-sm"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium">{sensor.name}</span>
                  <span className={`ltr text-xs ${SENSOR_STYLE[derivedState]}`}>
                    {derivedState}
                  </span>
                </div>
                <p className="ltr mt-1 text-xs text-muted">
                  {sensor.kind} · {sensor.mode}
                  {heartbeatAgeSeconds !== null
                    ? ` · hb ${Math.round(heartbeatAgeSeconds)}s`
                    : ' · no heartbeat'}
                </p>
                <p className="ltr mt-1 text-xs text-muted">
                  drops: {latest?.packetsDropped ?? 'n/a'} · lag: {latest?.eventLagSeconds ?? 'n/a'}
                  s
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="windows">
        <h2 id="windows" className="mb-3 text-lg font-medium">
          {t('noc.maintenance')}
        </h2>
        {ov.activeMaintenanceWindows.length === 0 ? (
          <p className="text-sm text-muted">{t('noc.no_maintenance')}</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {ov.activeMaintenanceWindows.map((w) => (
              <li key={w.id} className="rounded border border-border bg-surface px-3 py-2">
                <span className="ltr text-xs text-muted">
                  {w.assetId
                    ? `asset ${w.assetId.slice(0, 8)}`
                    : `segment ${w.segmentId?.slice(0, 8)}`}
                </span>{' '}
                · {w.reason} ·{' '}
                <span className="text-xs text-muted">
                  {when.format(new Date(w.startsAt))} → {when.format(new Date(w.endsAt))}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="recent">
        <h2 id="recent" className="mb-3 text-lg font-medium">
          {t('noc.recent_results')}
        </h2>
        {ov.recentResults.length === 0 ? (
          <p className="text-sm text-muted">{t('noc.no_results')}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('audit.time')}</th>
                  <th className="px-3 py-2 text-start">{t('noc.target')}</th>
                  <th className="px-3 py-2 text-start">{t('noc.outcome')}</th>
                  <th className="px-3 py-2 text-start">{t('noc.latency')}</th>
                  <th className="px-3 py-2 text-start">{t('noc.collector')}</th>
                </tr>
              </thead>
              <tbody>
                {ov.recentResults.map((r) => (
                  <tr key={r.id} className="border-t border-border">
                    <td className="px-3 py-2 text-xs">{when.format(new Date(r.observedAt))}</td>
                    <td className="ltr px-3 py-2 text-xs">
                      {r.kind} {r.target}
                    </td>
                    <td
                      className={`ltr px-3 py-2 text-xs ${r.outcome === 'up' ? 'text-ok' : r.outcome === 'down' || r.outcome === 'timeout' ? 'text-sev-critical' : 'text-muted'}`}
                    >
                      {r.outcome}
                    </td>
                    <td className="ltr px-3 py-2 text-xs tabular-nums">{r.latencyMs ?? '—'}</td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{r.collectorState}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
