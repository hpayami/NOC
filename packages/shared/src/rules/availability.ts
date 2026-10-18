import type { CheckOutcome, OperationalStatus, SensorHealthState } from '../enums';

export type CheckClass = 'up' | 'down' | 'path_loss' | 'unknown';

/** Heartbeat age after which a collector/sensor is considered silent. */
export const SENSOR_HEARTBEAT_TIMEOUT_SECONDS = 180;
/** A check whose latest result is older than this many intervals is treated as not arriving. */
export const STALE_RESULT_INTERVALS = 3;

export interface CollectorEvidence {
  heartbeatAgeSeconds: number | null;
  timeoutSeconds: number;
}

export interface CheckEvidence {
  intervalSeconds: number;
  latest: { outcome: CheckOutcome; observedAt: Date } | null;
  /** 'platform' when the management plane executed the check itself. */
  collector: CollectorEvidence | 'platform';
}

/**
 * Classifies one check's evidence. A silent collector or results that stopped arriving are a
 * monitoring-path problem (`path_loss`), never evidence that the device itself is down.
 */
export function classifyCheck(e: CheckEvidence, now: Date): CheckClass {
  if (e.collector !== 'platform') {
    const age = e.collector.heartbeatAgeSeconds;
    if (age === null || age > e.collector.timeoutSeconds) return 'path_loss';
  }
  if (!e.latest) return 'unknown';
  const ageSeconds = (now.getTime() - e.latest.observedAt.getTime()) / 1000;
  if (ageSeconds > e.intervalSeconds * STALE_RESULT_INTERVALS) return 'path_loss';
  switch (e.latest.outcome) {
    case 'up':
      return 'up';
    case 'down':
    case 'timeout':
      return 'down';
    default:
      return 'unknown';
  }
}

/**
 * Operational status from availability evidence. Maintenance wins; positive evidence (up/down)
 * wins over monitoring-path loss; mixed up/down is degraded; only path loss → the asset is not
 * reported offline, because we cannot see it.
 */
export function deriveOperationalStatus(input: {
  checks: CheckEvidence[];
  now: Date;
  inMaintenance: boolean;
}): { status: OperationalStatus; classes: CheckClass[] } {
  if (input.inMaintenance) return { status: 'maintenance', classes: [] };
  const classes = input.checks.map((c) => classifyCheck(c, input.now));
  if (classes.length === 0) return { status: 'unknown', classes };
  const up = classes.includes('up');
  const down = classes.includes('down');
  const pathLoss = classes.includes('path_loss');
  if (up && down) return { status: 'degraded', classes };
  if (up) return { status: 'online', classes };
  if (down) return { status: 'offline', classes };
  if (pathLoss) return { status: 'unreachable_monitoring_path', classes };
  return { status: 'unknown', classes };
}

export function deriveSensorHealth(i: {
  lastHeartbeatAt: Date | null;
  now: Date;
  timeoutSeconds?: number;
  reportedState: SensorHealthState | null;
}): SensorHealthState {
  const timeout = i.timeoutSeconds ?? SENSOR_HEARTBEAT_TIMEOUT_SECONDS;
  if (!i.lastHeartbeatAt) return 'silent';
  if ((i.now.getTime() - i.lastHeartbeatAt.getTime()) / 1000 > timeout) return 'silent';
  return i.reportedState ?? 'unknown';
}

export function isWindowActive(w: { startsAt: Date; endsAt: Date }, now: Date): boolean {
  return w.startsAt.getTime() <= now.getTime() && now.getTime() < w.endsAt.getTime();
}
