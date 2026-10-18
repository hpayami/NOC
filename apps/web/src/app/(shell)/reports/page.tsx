import { PostureReport, humanDuration, type SectionState } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import type { MessageKey } from '@/i18n/messages';

export const dynamic = 'force-dynamic';
const PERIODS = [7, 30, 90] as const;
const STATE_LABEL: Record<SectionState, MessageKey> = {
  available: 'rep.state.available',
  withheld: 'rep.state.withheld',
  not_configured: 'rep.state.not_configured',
  unavailable: 'rep.state.unavailable',
};
const STATE_TONE: Record<SectionState, string> = {
  available: 'text-ok',
  withheld: 'text-muted',
  not_configured: 'text-sev-low',
  unavailable: 'text-sev-critical',
};

type Section = {
  state: SectionState;
  permission: string;
  note: string | null;
  data: Record<string, unknown> | null;
};

export default async function ReportsPage({
  searchParams,
}: {
  searchParams: Promise<{ days?: string }>;
}) {
  const { t, locale } = await getI18n();
  const sp = await searchParams;
  const days = (PERIODS as readonly number[]).includes(Number(sp.days)) ? Number(sp.days) : 30;
  const r = await apiFetch(`/api/v1/reports/posture?days=${days}`, PostureReport);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  const counts = (c: unknown) =>
    Object.entries((c ?? {}) as Record<string, number>)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `${k} ${fmt.format(v)}`)
      .join(' · ') || '—';

  const sections: Array<{ key: MessageKey; s: Section; rows: Array<[MessageKey, string]> }> = [];
  const push = (
    key: MessageKey,
    s: Section,
    rows: (d: Record<string, unknown>) => Array<[MessageKey, string]>,
  ) => sections.push({ key, s, rows: s.data ? rows(s.data) : [] });
  const num = (v: unknown) => fmt.format(Number(v ?? 0));
  push('rep.assets', r.assets, (d) => [
    ['rep.total', num(d.total)],
    ['rep.seen_in_period', num(d.seenInPeriod)],
    ['rep.coverage', counts(d.byCoverage)],
    ['rep.criticality', counts(d.byCriticality)],
  ]);
  push('rep.sensors', r.sensors, (d) => [
    ['rep.total', `${num(d.total)} / ${t('ops.enabled')} ${num(d.enabled)}`],
    ['rep.heartbeating', `${num(d.heartbeating)} · ${t('rep.silent')} ${num(d.silent)}`],
    ['rep.inline_capable', num(d.inlineCapable)],
    ['rep.by_kind', counts(d.byKind)],
  ]);
  push('rep.events', r.events, (d) => [
    ['rep.total', `${num(d.total)} (${t('rep.sensors_reporting')} ${num(d.sensorsReporting)})`],
    ['rep.by_category', counts(d.byCategory)],
    ['rep.by_severity', counts(d.bySeverity)],
  ]);
  push('rep.alerts', r.alerts, (d) => [
    [
      'rep.opened',
      `${num(d.opened)} · ${t('rep.closed')} ${num(d.closedInPeriod)} · ${t('rep.false_positive')} ${num(d.falsePositives)}`,
    ],
    ['rep.open_at_end', num(d.openAtEnd)],
    ['rep.by_severity', counts(d.bySeverity)],
    ['rep.by_status', counts(d.byStatus)],
    [
      'rep.mtta',
      d.meanTimeToAcknowledgeSeconds === null
        ? t('rep.not_tracked')
        : humanDuration(d.meanTimeToAcknowledgeSeconds as number),
    ],
  ]);
  push('rep.incidents', r.incidents, (d) => [
    ['rep.opened', `${num(d.opened)} · ${t('rep.closed')} ${num(d.closed)}`],
    ['rep.open_at_end', num(d.openAtEnd)],
    ['rep.by_severity', counts(d.bySeverity)],
    ['rep.by_status', counts(d.byStatus)],
    [
      'rep.mttc',
      `${humanDuration(d.meanTimeToCloseSeconds as number | null)} / ${humanDuration(d.medianTimeToCloseSeconds as number | null)}`,
    ],
  ]);
  push('rep.response', r.response, (d) => [
    ['rep.proposed', num(d.proposed)],
    [
      'rep.executed',
      `${num(d.executed)} · ${t('rep.rolled_back')} ${num(d.rolledBack)} · ${t('rep.rejected')} ${num(d.rejected)}`,
    ],
    ['rep.by_status', counts(d.byStatus)],
  ]);
  push('rep.prevention', r.prevention, (d) => [
    ['rep.policies', `${num(d.policiesTotal)} (${counts(d.byStatus)})`],
    [
      'rep.enabled_now',
      `${num(d.enabledNow)} · ${t('rep.enabled_in_period')} ${num(d.enabledInPeriod)}`,
    ],
    ['rep.auto_disabled', num(d.autoDisabledInPeriod)],
    ['rep.sensors_inline', num(d.sensorsInline)],
  ]);
  push('rep.assessments', r.assessments, (d) => [
    ['rep.engagements', `${num(d.engagementsTotal)} (${counts(d.byStatus)})`],
    ['rep.runs', `${num(d.runsInPeriod)} (${counts(d.runsByStatus)})`],
  ]);
  push('rep.findings', r.findings, (d) => [
    ['rep.open', `${num(d.open)} (${counts(d.bySeverity)})`],
    ['rep.new_closed', `${num(d.newInPeriod)} / ${num(d.closedInPeriod)}`],
    ['rep.kev_open', num(d.knownExploitedOpen)],
    ['rep.cves', `${num(d.cveReferenced)} / ${num(d.cveCatalogued)}`],
  ]);
  push('rep.threat_intel', r.threatIntel, (d) => [
    ['rep.indicators', `${num(d.activeIndicators)} (${t('ti.sources')} ${num(d.sources)})`],
    ['rep.matches', `${num(d.matchesInPeriod)} (${counts(d.matchesByType)})`],
    ['ti.last_import', d.lastImportAt ? when.format(new Date(d.lastImportAt as string)) : '—'],
  ]);
  push('rep.analytics', r.analytics, (d) => [
    ['rep.scorings', `${num(d.scoringsInPeriod)} · ${t('rep.high_scores')} ${num(d.highScores)}`],
    ['rep.service', d.serviceReachable ? t('common.yes') : t('common.no')],
  ]);
  push('rep.governance', r.governance, (d) => [
    [
      'rep.audit_events',
      `${num(d.auditEventsInPeriod)} · ${t('rep.denied')} ${num(d.denied)} · ${t('rep.failures')} ${num(d.failures)}`,
    ],
    ['rep.logins', `${num(d.logins)} / ${num(d.loginFailures)}`],
    [
      'rep.chain',
      d.chainVerified === null
        ? t('rep.not_run')
        : d.chainVerified
          ? t('rep.chain_ok')
          : t('rep.chain_broken'),
    ],
  ]);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t('rep.title')}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted">{t('rep.subtitle')}</p>
          <p className="mt-2 text-xs text-muted" data-testid="report-period">
            {t('rep.period')}: {when.format(new Date(r.period.from))} →{' '}
            {when.format(new Date(r.period.to))} · {t('rep.scope')}:{' '}
            {r.sites === null ? t('rep.all_sites') : r.sites.join(', ') || t('rep.no_site')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {PERIODS.map((d) => (
            <a
              key={d}
              href={`/reports?days=${d}`}
              className={`rounded-md border px-3 py-1.5 text-sm ${d === days ? 'border-accent text-fg' : 'border-border text-muted hover:text-fg'}`}
            >
              {fmt.format(d)} {t('rep.days')}
            </a>
          ))}
          <a
            href={`/reports/download?days=${days}`}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-bg"
          >
            {t('rep.download')}
          </a>
        </div>
      </header>

      <section className="rounded-lg border border-border bg-surface p-4 text-sm">
        <h2 className="font-medium">{t('rep.limitations')}</h2>
        <ul className="ltr mt-1 list-disc space-y-0.5 ps-5 text-xs text-muted">
          {r.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </section>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {sections.map(({ key, s, rows }) => (
          <section
            key={key}
            className="rounded-lg border border-border bg-surface p-4"
            data-testid={`report-${key}`}
          >
            <div className="flex items-center justify-between gap-2">
              <h2 className="font-medium">{t(key)}</h2>
              <span
                className={`rounded border border-current px-1.5 py-0.5 text-[10px] uppercase ${STATE_TONE[s.state]}`}
              >
                {t(STATE_LABEL[s.state])}
              </span>
            </div>
            {s.state === 'withheld' ? (
              <p className="mt-2 text-xs text-muted">
                {t('rep.withheld_hint')} <span className="ltr">{s.permission}</span>
              </p>
            ) : s.note ? (
              <p className="ltr mt-2 text-xs text-muted">{s.note}</p>
            ) : null}
            {rows.length ? (
              <dl className="mt-3 space-y-1 text-xs">
                {rows.map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <dt className="text-muted">{t(k)}</dt>
                    <dd className="ltr text-end tabular-nums">{v}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </section>
        ))}
      </div>
    </div>
  );
}
