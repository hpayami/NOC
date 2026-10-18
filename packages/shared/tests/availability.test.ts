import { describe, expect, it } from 'vitest';
import {
  classifyCheck,
  deriveOperationalStatus,
  deriveSensorHealth,
  isWindowActive,
  type CheckEvidence,
} from '../src';

const now = new Date('2026-10-18T12:00:00Z');
const ago = (s: number) => new Date(now.getTime() - s * 1000);
const platform = (
  outcome: CheckEvidence['latest'] extends infer L
    ? L extends { outcome: infer O }
      ? O
      : never
    : never,
  ageSeconds = 10,
  intervalSeconds = 60,
): CheckEvidence => ({
  intervalSeconds,
  latest: { outcome, observedAt: ago(ageSeconds) },
  collector: 'platform',
});

describe('check classification', () => {
  it('maps outcomes', () => {
    expect(classifyCheck(platform('up'), now)).toBe('up');
    expect(classifyCheck(platform('down'), now)).toBe('down');
    expect(classifyCheck(platform('timeout'), now)).toBe('down');
    expect(classifyCheck(platform('error'), now)).toBe('unknown');
    expect(classifyCheck(platform('unsupported'), now)).toBe('unknown');
  });
  it('treats a silent collector as monitoring-path loss, not as device down', () => {
    const e: CheckEvidence = {
      intervalSeconds: 60,
      latest: { outcome: 'down', observedAt: ago(5) },
      collector: { heartbeatAgeSeconds: 900, timeoutSeconds: 180 },
    };
    expect(classifyCheck(e, now)).toBe('path_loss');
    expect(
      classifyCheck({ ...e, collector: { heartbeatAgeSeconds: null, timeoutSeconds: 180 } }, now),
    ).toBe('path_loss');
    expect(
      classifyCheck({ ...e, collector: { heartbeatAgeSeconds: 30, timeoutSeconds: 180 } }, now),
    ).toBe('down');
  });
  it('treats stale results as path loss', () => {
    expect(classifyCheck(platform('up', 60 * 4, 60), now)).toBe('path_loss');
    expect(classifyCheck({ intervalSeconds: 60, latest: null, collector: 'platform' }, now)).toBe(
      'unknown',
    );
  });
});

describe('operational status', () => {
  it('maintenance wins over everything', () => {
    expect(
      deriveOperationalStatus({ checks: [platform('down')], now, inMaintenance: true }).status,
    ).toBe('maintenance');
  });
  it('is unknown without checks', () => {
    expect(deriveOperationalStatus({ checks: [], now, inMaintenance: false }).status).toBe(
      'unknown',
    );
  });
  it('combines evidence: up, down, degraded, path loss', () => {
    expect(
      deriveOperationalStatus({ checks: [platform('up')], now, inMaintenance: false }).status,
    ).toBe('online');
    expect(
      deriveOperationalStatus({ checks: [platform('down')], now, inMaintenance: false }).status,
    ).toBe('offline');
    expect(
      deriveOperationalStatus({
        checks: [platform('up'), platform('down')],
        now,
        inMaintenance: false,
      }).status,
    ).toBe('degraded');
    const silent: CheckEvidence = {
      intervalSeconds: 60,
      latest: { outcome: 'down', observedAt: ago(5) },
      collector: { heartbeatAgeSeconds: null, timeoutSeconds: 180 },
    };
    expect(deriveOperationalStatus({ checks: [silent], now, inMaintenance: false }).status).toBe(
      'unreachable_monitoring_path',
    );
    // Positive evidence from another check outranks the path loss.
    expect(
      deriveOperationalStatus({ checks: [silent, platform('down')], now, inMaintenance: false })
        .status,
    ).toBe('offline');
    expect(
      deriveOperationalStatus({ checks: [silent, platform('up')], now, inMaintenance: false })
        .status,
    ).toBe('online');
  });
});

describe('sensor health and maintenance windows', () => {
  it('derives silent from heartbeat age and otherwise trusts the reported state', () => {
    expect(deriveSensorHealth({ lastHeartbeatAt: null, now, reportedState: 'healthy' })).toBe(
      'silent',
    );
    expect(deriveSensorHealth({ lastHeartbeatAt: ago(600), now, reportedState: 'healthy' })).toBe(
      'silent',
    );
    expect(deriveSensorHealth({ lastHeartbeatAt: ago(30), now, reportedState: 'degraded' })).toBe(
      'degraded',
    );
    expect(deriveSensorHealth({ lastHeartbeatAt: ago(30), now, reportedState: null })).toBe(
      'unknown',
    );
  });
  it('window is half-open [start, end)', () => {
    expect(isWindowActive({ startsAt: ago(10), endsAt: new Date(now.getTime() + 10) }, now)).toBe(
      true,
    );
    expect(isWindowActive({ startsAt: ago(10), endsAt: now }, now)).toBe(false);
    expect(isWindowActive({ startsAt: now, endsAt: new Date(now.getTime() + 10) }, now)).toBe(true);
  });
});
