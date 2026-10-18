import { describe, expect, it } from 'vitest';
import { sidOfExternalId, validationVerdict } from '../src';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

describe('detection validation verdict', () => {
  it('passes only when every expected signature fired on the expected bundle', () => {
    expect(
      validationVerdict({
        expectedSids: [1],
        firedSids: [1, 2],
        error: null,
        expectedBundleSha256: A,
        reportedBundleSha256: A,
      }),
    ).toEqual({ verdict: 'passed', missingSids: [], unexpectedCount: 1, detail: null });
    expect(
      validationVerdict({
        expectedSids: [1, 3],
        firedSids: [1],
        error: null,
        expectedBundleSha256: A,
        reportedBundleSha256: A,
      }),
    ).toMatchObject({
      verdict: 'failed',
      missingSids: [3],
      detail: 'expected signature(s) did not fire: 3',
    });
    expect(
      validationVerdict({
        expectedSids: [1],
        firedSids: [1],
        error: null,
        expectedBundleSha256: A,
        reportedBundleSha256: B,
      }),
    ).toMatchObject({
      verdict: 'inconclusive',
      detail: `sensor ran bundle ${B.slice(0, 12)}, expected ${A.slice(0, 12)}`,
    });
    expect(
      validationVerdict({
        expectedSids: [1],
        firedSids: [],
        error: 'sample missing',
        expectedBundleSha256: A,
        reportedBundleSha256: A,
      }),
    ).toMatchObject({ verdict: 'inconclusive', missingSids: [1], detail: 'sample missing' });
    expect(
      validationVerdict({
        expectedSids: [],
        firedSids: [5],
        error: null,
        expectedBundleSha256: null,
        reportedBundleSha256: null,
      }),
    ).toMatchObject({ verdict: 'inconclusive', unexpectedCount: 1 });
    // An unknown reported bundle (older agent) does not block a verdict; the platform cannot compare.
    expect(
      validationVerdict({
        expectedSids: [1],
        firedSids: [1],
        error: null,
        expectedBundleSha256: A,
        reportedBundleSha256: null,
      }).verdict,
    ).toBe('passed');
  });
  it('reads a sid only from gid:sid identities', () => {
    expect(sidOfExternalId('1:2001219')).toBe(2001219);
    expect(sidOfExternalId('2001219')).toBeNull();
    expect(sidOfExternalId('1:0')).toBeNull();
    expect(sidOfExternalId('zeek:conn-long')).toBeNull();
  });
});
