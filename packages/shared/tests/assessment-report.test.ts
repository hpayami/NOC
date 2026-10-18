import { describe, expect, it } from 'vitest';
import {
  EngagementReport,
  findingTarget,
  renderEngagementReportMarkdown,
  reportLimitations,
  targetCoverage,
  techniqueCoverage,
  type AssessmentRun,
  type EngagementRecord,
  type FindingRecord,
} from '../src';

const U = (hex: string) => `00000000-0000-4000-8000-${hex.padStart(12, '0')}`;
let seq = 0;
const run = (over: Partial<AssessmentRun>): AssessmentRun => ({
  id: U('1'),
  engagementId: U('e1'),
  scopeVersion: 1,
  technique: 'service_fingerprint',
  status: 'completed',
  dryRun: false,
  ports: [22],
  requestedBy: U('a1'),
  note: null,
  targetCount: 3,
  startedAt: '2026-10-18T10:00:00.000Z',
  finishedAt: '2026-10-18T10:01:00.000Z',
  summary: null,
  createdAt: '2026-10-18T09:59:00.000Z',
  ...over,
});
const finding = (target: string, over: Partial<FindingRecord> = {}): FindingRecord => ({
  id: U(`f${(seq++).toString(16)}`),
  assetId: U('1'),
  engagementId: U('e1'),
  title: 'SSH exposed on tcp/22',
  status: 'open',
  severity: 'medium',
  cve: [],
  cwe: [],
  cvssBaseScore: null,
  cvssVector: null,
  validated: true,
  evidenceRefs: [{ kind: 'note', ref: `assessment_run:${U('1')}:${target}:22` }],
  firstDetectedAt: '2026-10-18T10:00:30.000Z',
  lastDetectedAt: '2026-10-18T10:00:30.000Z',
  description: '',
  lastNote: null,
  updatedAt: '2026-10-18T10:00:30.000Z',
  ...over,
});
const engagement: EngagementRecord = {
  id: '00000000-0000-4000-8000-0000000000e1',
  reference: 'ENG-1',
  authorizingOrganization: 'Acme',
  authorizationReference: 'CTR-7',
  objective: 'Exposure review of the DMZ',
  status: 'active',
  responsibleOperatorId: '00000000-0000-4000-8000-0000000000a1',
  scope: {
    includeCidrs: [],
    includeAddresses: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
    excludeCidrs: [],
    excludeAddresses: [],
    allowPublicAddresses: false,
    allowedTechniques: ['host_discovery', 'service_fingerprint', 'web_scan'],
    windowStart: '2026-10-18T00:00:00.000Z',
    windowEnd: '2026-10-19T00:00:00.000Z',
    maxConcurrency: 2,
    maxRequestsPerSecond: 5,
  },
  scopeVersion: 2,
  approvedScopeVersion: 2,
  approvals: [],
  dataHandlingRestrictions: '',
  stopConditions: ['stop on request'],
  emergencyContact: 'soc@acme.test',
  evidenceRetentionDays: 365,
  activatedAt: null,
  completedAt: null,
  closeReason: null,
  runCount: 2,
  findingCount: 1,
  createdAt: '2026-10-18T09:00:00.000Z',
  updatedAt: '2026-10-18T09:00:00.000Z',
};

describe('engagement report', () => {
  it('derives technique status from live runs only and marks non-executable techniques', () => {
    const runs = [
      run({ id: U('1'), technique: 'service_fingerprint' }),
      run({ id: U('2'), technique: 'host_discovery', dryRun: true }),
      run({ id: U('3'), technique: 'host_discovery', status: 'failed' }),
    ];
    expect(techniqueCoverage(engagement.scope.allowedTechniques, runs)).toEqual([
      {
        technique: 'host_discovery',
        executable: true,
        liveRuns: 0,
        dryRuns: 1,
        status: 'dry_run_only',
      },
      {
        technique: 'service_fingerprint',
        executable: true,
        liveRuns: 1,
        dryRuns: 0,
        status: 'performed',
      },
      {
        technique: 'web_scan',
        executable: false,
        liveRuns: 0,
        dryRuns: 0,
        status: 'not_executable',
      },
    ]);
  });

  it('classifies every in-scope address honestly and keeps addresses probed under an older scope', () => {
    const runs = [run({ id: U('1'), scopeVersion: 1 }), run({ id: U('d'), dryRun: true })];
    const { targets, summary } = targetCoverage({
      scopeTargets: ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
      runs,
      runTargets: [
        {
          runId: U('1'),
          target: '10.0.0.1',
          decision: 'allowed',
          reasons: [],
          outcome: 'reachable',
          openPorts: [22],
          observedAt: '2026-10-18T10:00:10.000Z',
        },
        {
          runId: U('1'),
          target: '10.0.0.2',
          decision: 'allowed',
          reasons: [],
          outcome: 'unreachable',
          openPorts: [],
          observedAt: '2026-10-18T10:00:11.000Z',
        },
        {
          runId: U('1'),
          target: '10.0.0.3',
          decision: 'denied',
          reasons: ['window_closed'],
          outcome: 'skipped',
          openPorts: [],
          observedAt: '2026-10-18T10:00:12.000Z',
        },
        {
          runId: U('1'),
          target: '10.0.0.9',
          decision: 'allowed',
          reasons: [],
          outcome: 'reachable',
          openPorts: [80],
          observedAt: '2026-10-18T10:00:13.000Z',
        },
        // Dry-run rows never count as coverage.
        {
          runId: U('d'),
          target: '10.0.0.4',
          decision: 'allowed',
          reasons: [],
          outcome: 'skipped',
          openPorts: [],
          observedAt: null,
        },
      ],
      findings: [finding('10.0.0.1')],
    });
    expect(targets.map((t) => [t.target, t.status, t.outsideCurrentScope])).toEqual([
      ['10.0.0.1', 'assessed_with_findings', false],
      ['10.0.0.2', 'unreachable', false],
      ['10.0.0.3', 'denied', false],
      ['10.0.0.4', 'not_assessed', false],
      ['10.0.0.9', 'assessed_no_findings', true],
    ]);
    expect(targets[0]).toMatchObject({
      techniques: ['service_fingerprint'],
      openPorts: [22],
      findingCount: 1,
    });
    expect(targets[2]!.reasons).toEqual(['window_closed']);
    expect(summary).toEqual({
      targetsInScope: 4,
      assessedWithFindings: 1,
      assessedNoFindings: 0,
      unreachable: 1,
      denied: 1,
      notAssessed: 1,
      truncated: false,
    });
    expect(findingTarget(finding('10.0.0.1'))).toBe('10.0.0.1');
    expect(findingTarget(finding('x', { evidenceRefs: [] }))).toBeNull();
  });

  it('spells out limitations and renders them before the findings in Markdown', () => {
    const runs = [run({ id: U('1'), scopeVersion: 1 })];
    const techniques = techniqueCoverage(engagement.scope.allowedTechniques, runs);
    const { targets, summary } = targetCoverage({
      scopeTargets: engagement.scope.includeAddresses,
      runs,
      runTargets: [
        {
          runId: U('1'),
          target: '10.0.0.1',
          decision: 'allowed',
          reasons: [],
          outcome: 'reachable',
          openPorts: [22],
          observedAt: '2026-10-18T10:00:10.000Z',
        },
      ],
      findings: [finding('10.0.0.1', { validated: false })],
    });
    const limitations = reportLimitations({
      engagement,
      techniques,
      runs,
      coverage: summary,
      findingsIncluded: true,
      findings: [finding('10.0.0.1', { validated: false })],
    });
    expect(limitations.join('\n')).toMatch(/connect-level/);
    expect(limitations.join('\n')).toMatch(/web_scan .*no executor/);
    expect(limitations.join('\n')).toMatch(/host_discovery .*no live run/);
    expect(limitations.join('\n')).toMatch(/2 of 3 in-scope addresses were never probed/);
    expect(limitations.join('\n')).toMatch(/scope changed \(v1 → v2\)/);
    expect(limitations.join('\n')).toMatch(/1 findings are unvalidated/);
    expect(limitations.join('\n')).toMatch(/interim report/);
    const report = EngagementReport.parse({
      generatedAt: '2026-10-18T12:00:00.000Z',
      generatedBy: '00000000-0000-4000-8000-0000000000a1',
      engagement,
      techniques,
      runs,
      coverage: summary,
      targets,
      findings: [finding('10.0.0.1', { validated: false })],
      findingsIncluded: true,
      limitations,
    });
    const md = renderEngagementReportMarkdown(report);
    expect(md.indexOf('## Limitations')).toBeLessThan(md.indexOf('## Findings'));
    expect(md).toContain('# Assessment report — ENG-1');
    expect(md).toContain('| medium | SSH exposed on tcp/22 | 10.0.0.1 | open | no |');
    expect(md).toContain('| 10.0.0.2 | not_assessed |');
    expect(md).toContain('never contacted are reported as not assessed, never as secure');
    const withheld = renderEngagementReportMarkdown({
      ...report,
      findings: [],
      findingsIncluded: false,
    });
    expect(withheld).toContain('_Withheld');
  });
});
