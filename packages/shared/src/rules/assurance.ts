import type { AssuranceState } from '../enums';

export interface AssuranceInput {
  monitored: boolean;
  /** Is any engine able to detect on this asset's traffic at all? */
  detectionCapable: boolean;
  sensorHealthy: boolean;
  telemetryFresh: boolean;
  telemetryComplete: boolean;
  assessmentPerformed: boolean;
  openFindings: number;
  /** Alerts currently open against the asset. Alerts are reported separately from assurance. */
  activeAlerts: number;
}

/**
 * Returns every assurance state that applies, most limiting first. Visibility gaps always outrank
 * the absence of alerts: `no_threat_detected` appears only when the asset is monitored by a healthy
 * sensor with fresh, complete telemetry and has no open alerts. It is never a statement of security.
 */
export function deriveAssuranceStates(i: AssuranceInput): AssuranceState[] {
  if (!i.monitored) return ['asset_not_monitored'];
  if (!i.detectionCapable) return ['detection_unavailable'];
  if (!i.sensorHealthy) return ['sensor_unhealthy'];
  if (!i.telemetryFresh || !i.telemetryComplete) return ['telemetry_incomplete'];

  const states: AssuranceState[] = [];
  if (i.assessmentPerformed && i.openFindings > 0) states.push('assessment_with_findings');
  if (!i.assessmentPerformed) states.push('assessment_not_performed');
  if (i.activeAlerts === 0) states.push('no_threat_detected');
  return states;
}

/** The single most limiting state, for compact display. */
export function deriveAssuranceState(i: AssuranceInput): AssuranceState {
  return deriveAssuranceStates(i)[0] ?? 'no_threat_detected';
}
