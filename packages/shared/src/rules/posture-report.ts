import type { PostureReport, SectionState } from '../entities/reports';

const esc = (s: string) => s.replace(/[|\r\n]/g, ' ').trim();

export function humanDuration(seconds: number | null): string {
  if (seconds === null) return '—';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86_400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86_400).toFixed(1)} d`;
}

const counts = (c: Record<string, number>) =>
  Object.entries(c)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `${k} ${v}`)
    .join(', ') || '—';

const stateLine = (state: SectionState, permission: string, note: string | null): string => {
  switch (state) {
    case 'available':
      return note ? `_${esc(note)}_` : '';
    case 'withheld':
      return `_Withheld: this report was generated without \`${permission}\`; figures are not shown rather than estimated._`;
    case 'not_configured':
      return `_Not configured: ${note ? esc(note) : 'the platform holds no data of this kind'}._`;
    case 'unavailable':
      return `_Unavailable: ${note ? esc(note) : 'a dependency did not answer'}._`;
  }
};

/** Mean and median of positive durations, null when the input is empty. */
export function durationStats(seconds: readonly number[]): {
  mean: number | null;
  median: number | null;
} {
  const xs = seconds.filter((x) => Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (xs.length === 0) return { mean: null, median: null };
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  const mid = Math.floor(xs.length / 2);
  const median = xs.length % 2 ? xs[mid]! : (xs[mid - 1]! + xs[mid]!) / 2;
  return { mean: Math.round(mean), median: Math.round(median) };
}

/**
 * Deterministic Markdown rendering of a posture report. Every section prints its state first,
 * so a reader never mistakes "withheld" or "not configured" for zero activity.
 */
export function renderPostureReportMarkdown(r: PostureReport): string {
  const L: string[] = [];
  const sec = (
    title: string,
    s: { state: SectionState; permission: string; note: string | null },
    body: () => void,
  ) => {
    L.push(`## ${title}`, '');
    const line = stateLine(s.state, s.permission, s.note);
    if (line) L.push(line, '');
    if (s.state === 'available') body();
    L.push('');
  };
  L.push('# Security and network posture report', '');
  L.push(
    `Period ${r.period.from} → ${r.period.to} (${r.period.days} days). Generated ${r.generatedAt} by ${esc(r.generatedBy)}.`,
  );
  L.push(
    `Scope: ${r.sites === null ? 'all sites' : r.sites.length ? r.sites.join(', ') : 'no site (empty grant)'}.`,
    '',
  );
  L.push('## Limitations', '');
  for (const l of r.limitations) L.push(`- ${esc(l)}`);
  L.push('');

  sec('Assets', r.assets, () => {
    const d = r.assets.data!;
    L.push(`- Inventory: ${d.total}; seen in period: ${d.seenInPeriod}`);
    L.push(`- Coverage: ${counts(d.byCoverage)}`);
    L.push(`- Criticality: ${counts(d.byCriticality)}`);
  });
  sec('Sensors', r.sensors, () => {
    const d = r.sensors.data!;
    L.push(
      `- Registered ${d.total}, enabled ${d.enabled}, heartbeating ${d.heartbeating}, silent ${d.silent}, inline-capable ${d.inlineCapable}`,
    );
    L.push(`- By kind: ${counts(d.byKind)}`);
  });
  sec('Events', r.events, () => {
    const d = r.events.data!;
    L.push(`- Accepted events: ${d.total} from ${d.sensorsReporting} sensor(s)`);
    L.push(`- By category: ${counts(d.byCategory)}`);
    L.push(`- By severity: ${counts(d.bySeverity)}`);
  });
  sec('Alerts', r.alerts, () => {
    const d = r.alerts.data!;
    L.push(
      `- Opened ${d.opened}, closed ${d.closedInPeriod} (false positives ${d.falsePositives}), open at period end ${d.openAtEnd}`,
    );
    L.push(`- By severity: ${counts(d.bySeverity)}`);
    L.push(`- By status now: ${counts(d.byStatus)}`);
    L.push(
      `- Mean time to acknowledge: ${d.meanTimeToAcknowledgeSeconds === null ? 'not tracked' : humanDuration(d.meanTimeToAcknowledgeSeconds)}`,
    );
  });
  sec('Incidents', r.incidents, () => {
    const d = r.incidents.data!;
    L.push(`- Opened ${d.opened}, closed ${d.closed}, open at period end ${d.openAtEnd}`);
    L.push(`- By severity: ${counts(d.bySeverity)}; by status now: ${counts(d.byStatus)}`);
    L.push(
      `- Time to close (closed in period): mean ${humanDuration(d.meanTimeToCloseSeconds)}, median ${humanDuration(d.medianTimeToCloseSeconds)}`,
    );
  });
  sec('Response actions', r.response, () => {
    const d = r.response.data!;
    L.push(
      `- Proposed ${d.proposed}, executed ${d.executed}, rolled back ${d.rolledBack}, rejected ${d.rejected}`,
    );
    L.push(`- By status: ${counts(d.byStatus)}`);
  });
  sec('Inline prevention', r.prevention, () => {
    const d = r.prevention.data!;
    L.push(
      `- Policies ${d.policiesTotal} (${counts(d.byStatus)}); enabled now ${d.enabledNow}; enabled in period ${d.enabledInPeriod}; returned to detect-only by the watchdog ${d.autoDisabledInPeriod}`,
    );
    L.push(`- Sensors currently inline: ${d.sensorsInline}`);
  });
  sec('Authorised assessments', r.assessments, () => {
    const d = r.assessments.data!;
    L.push(`- Engagements ${d.engagementsTotal} (${counts(d.byStatus)})`);
    L.push(`- Runs in period ${d.runsInPeriod} (${counts(d.runsByStatus)})`);
  });
  sec('Findings and vulnerabilities', r.findings, () => {
    const d = r.findings.data!;
    L.push(
      `- Open ${d.open} (${counts(d.bySeverity)}); new in period ${d.newInPeriod}; closed in period ${d.closedInPeriod}`,
    );
    L.push(
      `- Known-exploited among open: ${d.knownExploitedOpen}; CVEs referenced ${d.cveReferenced}, catalogued ${d.cveCatalogued}`,
    );
  });
  sec('Threat intelligence', r.threatIntel, () => {
    const d = r.threatIntel.data!;
    L.push(
      `- Active indicators ${d.activeIndicators} from ${d.sources} source(s); last import ${d.lastImportAt ?? '—'}`,
    );
    L.push(`- Matches in period ${d.matchesInPeriod} (${counts(d.matchesByType)})`);
  });
  sec('Advisory analytics', r.analytics, () => {
    const d = r.analytics.data!;
    L.push(
      `- Scorings in period ${d.scoringsInPeriod}, high scores ${d.highScores}; service reachable: ${d.serviceReachable ? 'yes' : 'no'}`,
    );
  });
  sec('Governance and audit', r.governance, () => {
    const d = r.governance.data!;
    L.push(
      `- Audit events ${d.auditEventsInPeriod}: denied ${d.denied}, failures ${d.failures}; logins ${d.logins}, failed logins ${d.loginFailures}`,
    );
    L.push(
      `- Audit chain verified: ${d.chainVerified === null ? 'not run' : d.chainVerified ? 'intact' : 'BROKEN'}`,
    );
  });
  return (
    L.join('\n')
      .replace(/\n{3,}/g, '\n\n')
      .trimEnd() + '\n'
  );
}
