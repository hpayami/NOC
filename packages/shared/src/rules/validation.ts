import type { ValidationVerdict } from '../entities/validation';

export const VALIDATION_TTL_MINUTES = 30;
/** A passed validation counts as proof for this long when coverage is computed. */
export const VALIDATION_FRESH_DAYS = 30;

export interface VerdictInput {
  expectedSids: readonly number[];
  firedSids: readonly number[];
  error: string | null;
  expectedBundleSha256: string | null;
  reportedBundleSha256: string | null;
}

export interface VerdictResult {
  verdict: ValidationVerdict;
  missingSids: number[];
  unexpectedCount: number;
  detail: string | null;
}

/**
 * Pure verdict. `inconclusive` when the sensor could not run the sample or ran a different bundle
 * than the platform expected — a result from the wrong rules proves nothing either way.
 */
export function validationVerdict(input: VerdictInput): VerdictResult {
  const fired = new Set(input.firedSids);
  const missingSids = input.expectedSids.filter((s) => !fired.has(s));
  const expected = new Set(input.expectedSids);
  const unexpectedCount = [...fired].filter((s) => !expected.has(s)).length;
  if (input.error)
    return { verdict: 'inconclusive', missingSids, unexpectedCount, detail: input.error };
  if (
    input.expectedBundleSha256 &&
    input.reportedBundleSha256 &&
    input.expectedBundleSha256 !== input.reportedBundleSha256
  )
    return {
      verdict: 'inconclusive',
      missingSids,
      unexpectedCount,
      detail: `sensor ran bundle ${input.reportedBundleSha256.slice(0, 12)}, expected ${input.expectedBundleSha256.slice(0, 12)}`,
    };
  if (input.expectedSids.length === 0)
    return {
      verdict: 'inconclusive',
      missingSids,
      unexpectedCount,
      detail: 'rule has no signature id to expect',
    };
  return missingSids.length === 0
    ? { verdict: 'passed', missingSids, unexpectedCount, detail: null }
    : {
        verdict: 'failed',
        missingSids,
        unexpectedCount,
        detail: `expected signature(s) did not fire: ${missingSids.join(', ')}`,
      };
}

/** `gid:sid` → sid; anything else is not a Suricata signature reference. */
export function sidOfExternalId(externalId: string): number | null {
  const m = /^(\d+):(\d+)$/.exec(externalId);
  if (!m) return null;
  const sid = Number(m[2]);
  return Number.isInteger(sid) && sid > 0 ? sid : null;
}
