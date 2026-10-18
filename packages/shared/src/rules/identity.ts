export type MatchReason = 'agent_id' | 'cloud_instance_id' | 'mac_overlap' | 'hostname_segment';

export interface IdentityObservation {
  macAddresses: readonly string[];
  ipAddresses: readonly string[];
  hostnames: readonly string[];
  agentId?: string | null;
  cloudInstanceId?: string | null;
  /** Segment the observation was made in (inferred from address or declared by the collector). */
  segmentId?: string | null;
}

export interface CandidateAsset extends IdentityObservation {
  id: string;
}

export type ResolutionDecision =
  | {
      action: 'match';
      assetId: string;
      reason: MatchReason;
      confidence: number;
      conflicts: string[];
    }
  | { action: 'create'; reason: 'no_candidates' | 'no_stable_identifier_match'; confidence: number }
  | { action: 'ambiguous'; reason: MatchReason; candidateIds: string[] };

/** Confidence attached to a match by the identifier tier that produced it. */
export const MATCH_CONFIDENCE: Record<MatchReason, number> = {
  agent_id: 0.95,
  cloud_instance_id: 0.95,
  mac_overlap: 0.85,
  hostname_segment: 0.6,
};
export const CREATE_CONFIDENCE = 0.5;

const norm = (s: string) => s.trim().toLowerCase();
const overlaps = (a: readonly string[], b: readonly string[]) => {
  if (a.length === 0 || b.length === 0) return false;
  const set = new Set(a.map(norm));
  return b.some((x) => set.has(norm(x)));
};

/**
 * Deterministic asset identity resolution. Tiers are tried in order of identifier stability:
 * authenticated agent id → cloud instance id → MAC overlap → hostname within the same segment.
 * An IP address is never an identity: with no stable identifier in common the observation creates
 * a new asset. Two or more candidates matching on the same tier is reported as ambiguous and
 * nothing is merged — a human (or a stronger identifier) must decide.
 */
export function resolveAssetIdentity(
  obs: IdentityObservation,
  candidates: readonly CandidateAsset[],
): ResolutionDecision {
  if (candidates.length === 0)
    return { action: 'create', reason: 'no_candidates', confidence: CREATE_CONFIDENCE };

  const tiers: Array<[MatchReason, (c: CandidateAsset) => boolean]> = [
    ['agent_id', (c) => !!obs.agentId && !!c.agentId && obs.agentId === c.agentId],
    [
      'cloud_instance_id',
      (c) =>
        !!obs.cloudInstanceId && !!c.cloudInstanceId && obs.cloudInstanceId === c.cloudInstanceId,
    ],
    ['mac_overlap', (c) => overlaps(obs.macAddresses, c.macAddresses)],
    [
      'hostname_segment',
      (c) =>
        !!obs.segmentId && obs.segmentId === c.segmentId && overlaps(obs.hostnames, c.hostnames),
    ],
  ];

  for (const [reason, matches] of tiers) {
    const hits = candidates.filter(matches);
    if (hits.length > 1)
      return { action: 'ambiguous', reason, candidateIds: hits.map((h) => h.id) };
    if (hits.length === 1) {
      const hit = hits[0]!;
      return {
        action: 'match',
        assetId: hit.id,
        reason,
        confidence: MATCH_CONFIDENCE[reason],
        conflicts: detectConflicts(obs, hit),
      };
    }
  }
  return { action: 'create', reason: 'no_stable_identifier_match', confidence: CREATE_CONFIDENCE };
}

/** Disagreements between a matched candidate and the new observation; retained, never silently overwritten. */
export function detectConflicts(obs: IdentityObservation, c: CandidateAsset): string[] {
  const out: string[] = [];
  if (obs.agentId && c.agentId && obs.agentId !== c.agentId) out.push('agent_id_mismatch');
  if (obs.cloudInstanceId && c.cloudInstanceId && obs.cloudInstanceId !== c.cloudInstanceId)
    out.push('cloud_instance_id_mismatch');
  if (
    obs.macAddresses.length > 0 &&
    c.macAddresses.length > 0 &&
    !overlaps(obs.macAddresses, c.macAddresses)
  )
    out.push('mac_set_disjoint');
  if (obs.hostnames.length > 0 && c.hostnames.length > 0 && !overlaps(obs.hostnames, c.hostnames))
    out.push('hostname_mismatch');
  if (obs.segmentId && c.segmentId && obs.segmentId !== c.segmentId) out.push('segment_mismatch');
  return out;
}
