import type { Confidence, Criticality, Severity } from '../enums';

const SEVERITY_BASE: Record<Severity, number> = {
  info: 5,
  low: 25,
  medium: 50,
  high: 75,
  critical: 90,
};
const CONFIDENCE_MULT: Record<Confidence, number> = {
  unknown: 0.6,
  low: 0.7,
  medium: 0.85,
  high: 1,
};
const CRITICALITY_ADD: Record<Criticality, number> = {
  unclassified: 0,
  low: 0,
  medium: 4,
  high: 7,
  critical: 10,
};

export interface PriorityResult {
  score: number;
  factors: Array<{ factor: string; value: string; effect: string }>;
}

/** Deterministic, explainable alert priority. Severity, confidence and criticality stay separate inputs. */
export function computeAlertPriority(input: {
  severity: Severity;
  confidence: Confidence;
  assetCriticality: Criticality;
}): PriorityResult {
  const base = SEVERITY_BASE[input.severity];
  const mult = CONFIDENCE_MULT[input.confidence];
  const add = CRITICALITY_ADD[input.assetCriticality];
  const score = Math.min(100, Math.round(base * mult + add));
  return {
    score,
    factors: [
      { factor: 'severity', value: input.severity, effect: `base ${base}` },
      { factor: 'confidence', value: input.confidence, effect: `×${mult}` },
      { factor: 'asset_criticality', value: input.assetCriticality, effect: `+${add}` },
    ],
  };
}
