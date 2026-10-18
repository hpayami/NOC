import type { Severity } from '../enums';
import type { RiskLevel } from '../entities/assets';

/**
 * Curated MITRE ATT&CK® subset: only techniques this platform can actually attribute (from rule
 * metadata or from an exposed service). Anything outside the catalogue is reported by id with
 * `name: null` — never guessed.
 */
export const ATTACK_TECHNIQUES: Record<string, { name: string; tactic: string }> = {
  T1595: { name: 'Active Scanning', tactic: 'reconnaissance' },
  T1046: { name: 'Network Service Discovery', tactic: 'discovery' },
  T1018: { name: 'Remote System Discovery', tactic: 'discovery' },
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
  T1133: { name: 'External Remote Services', tactic: 'initial-access' },
  T1078: { name: 'Valid Accounts', tactic: 'defense-evasion' },
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'execution' },
  T1021: { name: 'Remote Services', tactic: 'lateral-movement' },
  'T1021.001': { name: 'Remote Desktop Protocol', tactic: 'lateral-movement' },
  'T1021.002': { name: 'SMB/Windows Admin Shares', tactic: 'lateral-movement' },
  'T1021.004': { name: 'SSH', tactic: 'lateral-movement' },
  'T1021.005': { name: 'VNC', tactic: 'lateral-movement' },
  T1210: { name: 'Exploitation of Remote Services', tactic: 'lateral-movement' },
  T1110: { name: 'Brute Force', tactic: 'credential-access' },
  'T1110.001': { name: 'Password Guessing', tactic: 'credential-access' },
  T1040: { name: 'Network Sniffing', tactic: 'credential-access' },
  T1557: { name: 'Adversary-in-the-Middle', tactic: 'credential-access' },
  T1552: { name: 'Unsecured Credentials', tactic: 'credential-access' },
  T1213: { name: 'Data from Information Repositories', tactic: 'collection' },
  T1071: { name: 'Application Layer Protocol', tactic: 'command-and-control' },
  'T1071.001': { name: 'Web Protocols', tactic: 'command-and-control' },
  T1571: { name: 'Non-Standard Port', tactic: 'command-and-control' },
  T1105: { name: 'Ingress Tool Transfer', tactic: 'command-and-control' },
  T1041: { name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration' },
  T1498: { name: 'Network Denial of Service', tactic: 'impact' },
  T1499: { name: 'Endpoint Denial of Service', tactic: 'impact' },
  T1565: { name: 'Data Manipulation', tactic: 'impact' },
};

export const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;

export function techniqueInfo(id: string): { name: string | null; tactic: string | null } {
  const hit = ATTACK_TECHNIQUES[id];
  return hit ? { name: hit.name, tactic: hit.tactic } : { name: null, tactic: null };
}

/**
 * Techniques an exposed service makes *available* to an adversary. This is exposure, not an
 * observation: the profile labels these `source: 'exposure'` so they are never read as attacks seen.
 */
export const EXPOSURE_TECHNIQUES: Readonly<Record<number, readonly string[]>> = {
  21: ['T1040', 'T1110'],
  22: ['T1021.004', 'T1110'],
  23: ['T1040', 'T1021', 'T1110'],
  25: ['T1071'],
  80: ['T1190', 'T1071.001'],
  139: ['T1021.002', 'T1210'],
  443: ['T1190', 'T1071.001'],
  445: ['T1021.002', 'T1210'],
  1433: ['T1190', 'T1213', 'T1110'],
  3306: ['T1190', 'T1213', 'T1110'],
  3389: ['T1021.001', 'T1133', 'T1110'],
  5432: ['T1190', 'T1213', 'T1110'],
  5900: ['T1021.005', 'T1110'],
  6379: ['T1190', 'T1213', 'T1552'],
  8080: ['T1190', 'T1071.001'],
  9200: ['T1190', 'T1213', 'T1552'],
  11211: ['T1190', 'T1213'],
  27017: ['T1190', 'T1213', 'T1552'],
};

export const exposureTechniques = (port: number): readonly string[] =>
  EXPOSURE_TECHNIQUES[port] ?? [];

const SEV_POINTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
  info: 1,
};

export interface RiskInput {
  monitoringCoverage: string;
  assuranceState: string;
  openFindings: ReadonlyArray<{ severity: Severity; validated: boolean }>;
  openAlerts: ReadonlyArray<{ severity: Severity }>;
  exposures: ReadonlyArray<{ port: number; severity: Severity | null }>;
  criticality: string;
}

export interface RiskAssessment {
  level: RiskLevel;
  /** 0–100, monotone in the evidence; comparable across assets, not a probability. */
  score: number;
  /** How much telemetry stands behind the level. */
  confidence: 'high' | 'medium' | 'low';
  basis: string[];
}

/**
 * Deterministic risk from evidence the platform holds. Two honesty rules: an asset with no
 * detection coverage, no findings and no alerts is `unknown`, never `none`; and the score is
 * explained line by line so an operator can dispute each input.
 */
export function assessAssetRisk(input: RiskInput): RiskAssessment {
  const basis: string[] = [];
  let score = 0;
  const monitored =
    input.monitoringCoverage === 'monitored' || input.monitoringCoverage === 'partial';
  for (const f of input.openFindings) {
    const pts = SEV_POINTS[f.severity] * (f.validated ? 1 : 0.6);
    score += pts;
  }
  if (input.openFindings.length) {
    const top = input.openFindings
      .map((f) => f.severity)
      .sort((a, b) => SEV_POINTS[b] - SEV_POINTS[a])[0];
    basis.push(
      `${input.openFindings.length} open finding(s), highest ${top}${input.openFindings.some((f) => !f.validated) ? ' (some unvalidated)' : ''}`,
    );
  }
  for (const a of input.openAlerts) score += SEV_POINTS[a.severity] * 0.8;
  if (input.openAlerts.length) {
    const top = input.openAlerts
      .map((a) => a.severity)
      .sort((a, b) => SEV_POINTS[b] - SEV_POINTS[a])[0];
    basis.push(`${input.openAlerts.length} open alert(s), highest ${top}`);
  }
  const risky = input.exposures.filter((e) => e.severity !== null);
  for (const e of risky) score += SEV_POINTS[e.severity!] * 0.5;
  if (input.exposures.length)
    basis.push(
      `${input.exposures.length} open port(s), ${risky.length} on risky services${risky.length ? ` (${risky.map((e) => e.port).join(', ')})` : ''}`,
    );
  if (input.criticality === 'critical' || input.criticality === 'high') {
    score *= input.criticality === 'critical' ? 1.5 : 1.25;
    basis.push(`asset criticality ${input.criticality} amplifies the score`);
  }
  score = Math.min(100, Math.round(score));
  const noEvidence =
    input.openFindings.length === 0 &&
    input.openAlerts.length === 0 &&
    input.exposures.length === 0;
  if (!monitored && noEvidence) {
    basis.push(
      `no detection coverage (${input.monitoringCoverage}) and no assessment: absence of alerts is not evidence of safety`,
    );
    return { level: 'unknown', score: 0, confidence: 'low', basis };
  }
  const level: RiskLevel =
    score >= 60
      ? 'critical'
      : score >= 35
        ? 'high'
        : score >= 15
          ? 'medium'
          : score > 0
            ? 'low'
            : 'none';
  if (level === 'none')
    basis.push(
      monitored
        ? 'monitored, no open findings, alerts or risky exposures'
        : 'no open findings, alerts or risky exposures, but the asset is not monitored',
    );
  const confidence: RiskAssessment['confidence'] = monitored
    ? input.assuranceState === 'sensor_unhealthy' || input.assuranceState === 'telemetry_incomplete'
      ? 'medium'
      : 'high'
    : input.openFindings.length
      ? 'medium'
      : 'low';
  return { level, score, confidence, basis };
}
