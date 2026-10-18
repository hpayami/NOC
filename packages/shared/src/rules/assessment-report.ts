import type { AssessmentTechnique } from '../enums';
import {
  EXECUTABLE_TECHNIQUES,
  type AssessmentRun,
  type CoverageSummary,
  type EngagementRecord,
  type EngagementReport,
  type FindingRecord,
  type RunTarget,
  type TargetCoverage,
  type TechniqueCoverage,
} from '../entities/assessments';

export const REPORT_MAX_TARGETS = 5000;
const MARKDOWN_MAX_TARGET_ROWS = 500;

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Findings recorded by assessment runs reference `assessment_run:<run>:<target>:<port>`. */
export function findingTarget(f: FindingRecord): string | null {
  for (const e of f.evidenceRefs) {
    const m = /^assessment_run:[^:]+:([^:]+):\d+$/.exec(e.ref);
    if (m) return m[1]!;
  }
  return null;
}

export function techniqueCoverage(
  allowed: readonly AssessmentTechnique[],
  runs: readonly AssessmentRun[],
): TechniqueCoverage[] {
  return allowed.map((technique) => {
    const mine = runs.filter((r) => r.technique === technique);
    const liveRuns = mine.filter((r) => !r.dryRun && r.status === 'completed').length;
    const dryRuns = mine.filter((r) => r.dryRun && r.status === 'completed').length;
    const executable = EXECUTABLE_TECHNIQUES.includes(technique);
    const status: TechniqueCoverage['status'] = !executable
      ? 'not_executable'
      : liveRuns > 0
        ? 'performed'
        : dryRuns > 0
          ? 'dry_run_only'
          : 'not_performed';
    return { technique, executable, liveRuns, dryRuns, status };
  });
}

/**
 * Per-address coverage from live (non-dry) run targets. Precedence: findings > reachable >
 * unreachable > denied > not assessed. Addresses probed by an older scope version but no longer
 * in scope are kept and flagged, never dropped — the report must account for every connection
 * the platform made.
 */
export function targetCoverage(input: {
  scopeTargets: readonly string[];
  runs: readonly AssessmentRun[];
  runTargets: ReadonlyArray<RunTarget & { runId: string }>;
  findings: readonly FindingRecord[];
}): { targets: TargetCoverage[]; summary: CoverageSummary } {
  const liveRuns = new Map(input.runs.filter((r) => !r.dryRun).map((r) => [r.id, r]));
  const byTarget = new Map<string, Array<RunTarget & { technique: AssessmentTechnique }>>();
  for (const t of input.runTargets) {
    const run = liveRuns.get(t.runId);
    if (!run) continue;
    const list = byTarget.get(t.target) ?? [];
    list.push({ ...t, technique: run.technique });
    byTarget.set(t.target, list);
  }
  const findingsByTarget = new Map<string, number>();
  for (const f of input.findings) {
    const target = findingTarget(f);
    if (target) findingsByTarget.set(target, (findingsByTarget.get(target) ?? 0) + 1);
  }
  const inScope = new Set(input.scopeTargets);
  const all = [...inScope, ...[...byTarget.keys()].filter((t) => !inScope.has(t))];
  const truncated = all.length > REPORT_MAX_TARGETS;
  const targets: TargetCoverage[] = all.slice(0, REPORT_MAX_TARGETS).map((target) => {
    const probes = byTarget.get(target) ?? [];
    const findingCount = findingsByTarget.get(target) ?? 0;
    const reachable = probes.some((p) => p.outcome === 'reachable');
    const unreachable = probes.some((p) => p.outcome === 'unreachable');
    const denied = probes.some((p) => p.decision === 'denied');
    const status: TargetCoverage['status'] =
      findingCount > 0
        ? 'assessed_with_findings'
        : reachable
          ? 'assessed_no_findings'
          : unreachable
            ? 'unreachable'
            : denied
              ? 'denied'
              : 'not_assessed';
    const observed = probes
      .map((p) => p.observedAt)
      .filter((x): x is string => !!x)
      .sort();
    return {
      target,
      status,
      techniques: [
        ...new Set(
          probes
            .filter((p) => p.outcome === 'reachable' || p.outcome === 'unreachable')
            .map((p) => p.technique),
        ),
      ],
      openPorts: [...new Set(probes.flatMap((p) => p.openPorts))]
        .sort((a, b) => a - b)
        .slice(0, 64),
      findingCount,
      reasons: [...new Set(probes.flatMap((p) => p.reasons))].slice(0, 16),
      lastObservedAt: observed[observed.length - 1] ?? null,
      outsideCurrentScope: !inScope.has(target),
    };
  });
  const count = (s: TargetCoverage['status']) =>
    targets.filter((t) => t.status === s && !t.outsideCurrentScope).length;
  return {
    targets,
    summary: {
      targetsInScope: input.scopeTargets.length,
      assessedWithFindings: count('assessed_with_findings'),
      assessedNoFindings: count('assessed_no_findings'),
      unreachable: count('unreachable'),
      denied: count('denied'),
      notAssessed: count('not_assessed'),
      truncated,
    },
  };
}

/** The honest part. Every reader of the report sees these before any finding. */
export function reportLimitations(input: {
  engagement: EngagementRecord;
  techniques: readonly TechniqueCoverage[];
  runs: readonly AssessmentRun[];
  coverage: CoverageSummary;
  findingsIncluded: boolean;
  findings: readonly FindingRecord[];
}): string[] {
  const out: string[] = [];
  const e = input.engagement;
  out.push(
    'Platform-executed techniques are connect-level (TCP reachability and service exposure). They are not a vulnerability assessment, exploitation or configuration audit.',
  );
  for (const t of input.techniques) {
    if (t.status === 'not_executable')
      out.push(
        `Technique ${t.technique} is authorised but has no executor in this platform: not performed.`,
      );
    else if (t.status === 'not_performed')
      out.push(`Technique ${t.technique} is authorised but no live run completed: not performed.`);
    else if (t.status === 'dry_run_only')
      out.push(
        `Technique ${t.technique} only ran in dry-run mode (scope evaluation, no connections): not performed.`,
      );
  }
  if (input.coverage.notAssessed > 0)
    out.push(
      `${input.coverage.notAssessed} of ${input.coverage.targetsInScope} in-scope addresses were never probed by a live run: not assessed.`,
    );
  if (input.coverage.denied > 0)
    out.push(
      `${input.coverage.denied} in-scope addresses were refused by the scope check at run time (window, exclusions or policy) and not contacted.`,
    );
  if (input.coverage.unreachable > 0)
    out.push(
      `${input.coverage.unreachable} addresses did not answer on any probed port; absence of a response is not evidence of absence of a host.`,
    );
  if (input.coverage.truncated)
    out.push(
      `The scope enumerates more than ${REPORT_MAX_TARGETS} addresses; the target table is truncated and the counts cover the listed addresses only.`,
    );
  const lastLive = input.runs
    .filter((r) => !r.dryRun && r.status === 'completed')
    .map((r) => r.scopeVersion)
    .sort((a, b) => b - a)[0];
  if (lastLive !== undefined && lastLive < e.scopeVersion)
    out.push(
      `The scope changed (v${lastLive} → v${e.scopeVersion}) after the last live run; coverage refers to the current scope, runs refer to the version they ran against.`,
    );
  if (e.approvedScopeVersion !== e.scopeVersion)
    out.push('The current scope version is not approved.');
  if (!input.findingsIncluded)
    out.push('Findings are withheld: the requester does not hold findings.read.');
  else if (input.findings.some((f) => !f.validated))
    out.push(
      `${input.findings.filter((f) => !f.validated).length} findings are unvalidated observations (exposure of a risky service), not confirmed vulnerabilities.`,
    );
  if (e.status !== 'completed')
    out.push(`The engagement is ${e.status}, not completed: this is an interim report.`);
  return out;
}

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const yesNo = (b: boolean) => (b ? 'yes' : 'no');

/** Shareable Markdown rendering of a report. Limitations come before findings on purpose. */
export function renderEngagementReportMarkdown(r: EngagementReport): string {
  const e = r.engagement;
  const lines: string[] = [];
  lines.push(`# Assessment report — ${esc(e.reference)}`, '');
  lines.push(`Generated ${r.generatedAt} by ${r.generatedBy}. Status: **${e.status}**.`, '');
  lines.push('## Authorisation', '');
  lines.push(`- Authorising organisation: ${esc(e.authorizingOrganization)}`);
  lines.push(`- Authorisation reference: ${esc(e.authorizationReference)}`);
  lines.push(`- Responsible operator: ${e.responsibleOperatorId}`);
  lines.push(
    `- Approvals: ${e.approvals.length ? e.approvals.map((a) => `${a.decision} (scope v${a.scopeVersion}) by ${a.approverId}`).join('; ') : 'none'}`,
  );
  lines.push(`- Objective: ${esc(e.objective)}`, '');
  lines.push('## Scope', '');
  lines.push(`- Version: ${e.scopeVersion} (approved: ${e.approvedScopeVersion ?? 'none'})`);
  lines.push(
    `- Include: ${[...e.scope.includeCidrs, ...e.scope.includeAddresses].join(', ') || '—'}`,
  );
  lines.push(
    `- Exclude: ${[...e.scope.excludeCidrs, ...e.scope.excludeAddresses].join(', ') || '—'}`,
  );
  lines.push(`- Window: ${e.scope.windowStart} → ${e.scope.windowEnd}`);
  lines.push(`- Public addresses allowed: ${yesNo(e.scope.allowPublicAddresses)}`);
  lines.push(`- Stop conditions: ${e.stopConditions.map(esc).join('; ') || '—'}`, '');
  lines.push('## Limitations', '');
  for (const l of r.limitations) lines.push(`- ${esc(l)}`);
  lines.push('', '## Techniques', '');
  lines.push('| Technique | Executable here | Live runs | Dry runs | Status |');
  lines.push('| --- | --- | ---: | ---: | --- |');
  for (const t of r.techniques)
    lines.push(
      `| ${t.technique} | ${yesNo(t.executable)} | ${t.liveRuns} | ${t.dryRuns} | ${t.status} |`,
    );
  lines.push('', '## Coverage', '');
  const c = r.coverage;
  lines.push(`- In-scope addresses: ${c.targetsInScope}${c.truncated ? ' (truncated)' : ''}`);
  lines.push(`- Assessed, with findings: ${c.assessedWithFindings}`);
  lines.push(`- Assessed, no findings: ${c.assessedNoFindings}`);
  lines.push(`- Unreachable: ${c.unreachable}`);
  lines.push(`- Denied at run time: ${c.denied}`);
  lines.push(`- Not assessed: ${c.notAssessed}`, '');
  lines.push('## Findings', '');
  if (!r.findingsIncluded) lines.push('_Withheld (requester lacks findings.read)._');
  else if (r.findings.length === 0) lines.push('_No findings recorded for this engagement._');
  else {
    lines.push('| Severity | Title | Target | Status | Validated | First seen | Last seen |');
    lines.push('| --- | --- | --- | --- | --- | --- | --- |');
    const sorted = [...r.findings].sort(
      (a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9),
    );
    for (const f of sorted)
      lines.push(
        `| ${f.severity} | ${esc(f.title)} | ${findingTarget(f) ?? f.assetId} | ${f.status} | ${yesNo(f.validated)} | ${f.firstDetectedAt} | ${f.lastDetectedAt} |`,
      );
  }
  lines.push('', '## Runs', '');
  if (r.runs.length === 0) lines.push('_No runs._');
  else {
    lines.push('| Started | Technique | Mode | Status | Scope v | Targets | Reachable | Denied |');
    lines.push('| --- | --- | --- | --- | ---: | ---: | ---: | ---: |');
    for (const run of r.runs)
      lines.push(
        `| ${run.startedAt ?? run.createdAt} | ${run.technique} | ${run.dryRun ? 'dry run' : 'live'} | ${run.status} | ${run.scopeVersion} | ${run.targetCount} | ${run.summary?.reachable ?? '—'} | ${run.summary?.denied ?? '—'} |`,
      );
  }
  lines.push('', '## Targets', '');
  const rows = r.targets.slice(0, MARKDOWN_MAX_TARGET_ROWS);
  lines.push(
    '| Address | Status | Techniques | Open ports | Findings | Last observed | In current scope |',
  );
  lines.push('| --- | --- | --- | --- | ---: | --- | --- |');
  for (const t of rows)
    lines.push(
      `| ${t.target} | ${t.status} | ${t.techniques.join(', ') || '—'} | ${t.openPorts.join(', ') || '—'} | ${t.findingCount} | ${t.lastObservedAt ?? '—'} | ${yesNo(!t.outsideCurrentScope)} |`,
    );
  if (r.targets.length > rows.length)
    lines.push(
      '',
      `_${r.targets.length - rows.length} more addresses omitted from this rendering; the JSON report lists them all._`,
    );
  lines.push('', '---', '');
  lines.push(
    '_Produced by the platform from its own run records. Addresses the platform never contacted are reported as not assessed, never as secure._',
  );
  return lines.join('\n') + '\n';
}
