import { describe, expect, it } from 'vitest';
import { PostureReport, durationStats, humanDuration, renderPostureReportMarkdown } from '../src';

const withheld = (permission: string) => ({
  state: 'withheld' as const,
  permission,
  note: null,
  data: null,
});

describe('posture report rendering', () => {
  it('computes duration statistics without inventing values', () => {
    expect(durationStats([])).toEqual({ mean: null, median: null });
    expect(durationStats([60, 120, 600])).toEqual({ mean: 260, median: 120 });
    expect(durationStats([10, 20])).toEqual({ mean: 15, median: 15 });
    expect(durationStats([-1, NaN, 30])).toEqual({ mean: 30, median: 30 });
    expect(humanDuration(null)).toBe('—');
    expect(humanDuration(45)).toBe('45 s');
    expect(humanDuration(90)).toBe('1.5 min');
    expect(humanDuration(7200)).toBe('2.0 h');
    expect(humanDuration(3 * 86_400)).toBe('3.0 d');
  });

  it('renders every section with its state first, never showing figures for withheld or empty planes', () => {
    const r = PostureReport.parse({
      generatedAt: '2026-10-18T10:00:00.000Z',
      generatedBy: 'analyst@test.local',
      period: { from: '2026-09-18T10:00:00.000Z', to: '2026-10-18T10:00:00.000Z', days: 30 },
      sites: ['dc1'],
      assets: withheld('assets.read'),
      sensors: withheld('sensors.read'),
      events: {
        state: 'not_configured',
        permission: 'events.read',
        note: 'no event accepted in the period',
        data: null,
      },
      alerts: {
        state: 'available',
        permission: 'alerts.read',
        note: null,
        data: {
          opened: 12,
          bySeverity: { high: 2, low: 10 },
          byStatus: { new: 3, resolved: 9 },
          openAtEnd: 3,
          closedInPeriod: 9,
          falsePositives: 1,
          meanTimeToAcknowledgeSeconds: null,
        },
      },
      incidents: {
        state: 'available',
        permission: 'incidents.read',
        note: null,
        data: {
          opened: 2,
          closed: 1,
          openAtEnd: 1,
          bySeverity: { high: 2 },
          byStatus: { closed: 1, triage: 1 },
          meanTimeToCloseSeconds: 5400,
          medianTimeToCloseSeconds: 5400,
        },
      },
      response: withheld('response.read'),
      prevention: {
        state: 'not_configured',
        permission: 'ips.read',
        note: 'no inline-prevention policy proposed; sensors run detect-only',
        data: null,
      },
      assessments: withheld('assessments.read'),
      findings: withheld('findings.read'),
      threatIntel: withheld('threat_intel.read'),
      analytics: {
        state: 'unavailable',
        permission: 'ml.read',
        note: 'analysis service unreachable',
        data: null,
      },
      governance: withheld('audit.read'),
      limitations: ['Figures are counts of records the platform holds.'],
    });
    const md = renderPostureReportMarkdown(r);
    expect(md.startsWith('# Security and network posture report\n')).toBe(true);
    expect(md).toContain('Scope: dc1.');
    expect(md).toContain(
      '## Assets\n\n_Withheld: this report was generated without `assets.read`; figures are not shown rather than estimated._',
    );
    expect(md).toContain('## Events\n\n_Not configured: no event accepted in the period._');
    expect(md).toContain('- Opened 12, closed 9 (false positives 1), open at period end 3');
    expect(md).toContain('- By severity: high 2, low 10');
    expect(md).toContain('- Mean time to acknowledge: not tracked');
    expect(md).toContain('- Time to close (closed in period): mean 1.5 h, median 1.5 h');
    expect(md).toContain('## Advisory analytics\n\n_Unavailable: analysis service unreachable._');
    expect(md).not.toMatch(/undefined|NaN|\[object/);
    // Deterministic: the same report renders identically.
    expect(renderPostureReportMarkdown(r)).toBe(md);
  });
});
