import { EventStats } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';

export const dynamic = 'force-dynamic';

export default async function NidsPage() {
  const { t, locale } = await getI18n();
  const stats = await apiFetch('/api/v1/events/stats?hours=24', EventStats);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const types = Object.entries(stats.byType).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('nids.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('nids.subtitle')}</p>
      </header>

      <section aria-labelledby="sensors">
        <h2 id="sensors" className="mb-3 text-lg font-medium">
          {t('nids.sensors')}
        </h2>
        {stats.sensors.length === 0 ? (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm">
            <p>{t('nids.no_sensors')}</p>
            <p className="mt-1 text-xs text-muted">{t('nids.no_sensors_hint')}</p>
          </div>
        ) : (
          <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {stats.sensors.map((s) => (
              <li
                key={s.sensorId}
                className="rounded-lg border border-border bg-surface p-4 text-sm"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium">{s.name}</span>
                  <span className="ltr text-xs text-muted">{s.kind}</span>
                </div>
                <p className="mt-2 text-xs text-muted">
                  {t('nids.events_24h')}:{' '}
                  <span className="ltr tabular-nums">{fmt.format(s.events)}</span>
                </p>
                <p className="text-xs text-muted">
                  {t('nids.last_event')}:{' '}
                  {s.lastEventAt ? when.format(new Date(s.lastEventAt)) : t('nids.never')}
                  {s.lagSeconds !== null ? (
                    <span
                      className={`ltr ms-1 ${s.lagSeconds > 600 ? 'text-sev-high' : 'text-ok'}`}
                    >
                      ({Math.round(s.lagSeconds)}s)
                    </span>
                  ) : null}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="types">
        <h2 id="types" className="mb-3 text-lg font-medium">
          {t('nids.by_type')} ({fmt.format(stats.total)})
        </h2>
        {types.length === 0 ? (
          <p className="text-sm text-muted">{t('nids.no_events')}</p>
        ) : (
          <ul className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            {types.map(([type, n]) => (
              <li key={type} className="rounded-lg border border-border bg-surface p-3">
                <p className="ltr text-xs text-muted">{type}</p>
                <p className="mt-1 text-2xl font-semibold tabular-nums">{fmt.format(n)}</p>
              </li>
            ))}
          </ul>
        )}
        <ul className="mt-3 flex flex-wrap gap-2 text-xs">
          {Object.entries(stats.bySeverity).map(([sev, n]) => (
            <li
              key={sev}
              className="ltr rounded border border-border bg-surface px-2 py-1 text-muted"
            >
              {sev}: {fmt.format(n)}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
