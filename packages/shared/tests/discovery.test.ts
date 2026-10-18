import { describe, expect, it } from 'vitest';
import {
  cidrWithin,
  expandTargets,
  validateDiscoveryScope,
  type AuthorizedTargetScope,
  type SegmentPolicy,
} from '../src';

const segments: SegmentPolicy[] = [
  { id: 'lab', cidr: '10.20.0.0/16', activeDiscoveryAllowed: true },
  { id: 'mgmt', cidr: '10.99.0.0/16', activeDiscoveryAllowed: false },
];
const scope = (over: Partial<AuthorizedTargetScope> = {}): AuthorizedTargetScope => ({
  includeCidrs: ['10.20.5.0/28'],
  includeAddresses: [],
  excludeCidrs: [],
  excludeAddresses: ['10.20.5.3'],
  allowPublicAddresses: false,
  allowedTechniques: ['host_discovery'],
  windowStart: '2026-10-18T00:00:00Z',
  windowEnd: '2026-10-19T00:00:00Z',
  maxConcurrency: 4,
  maxRequestsPerSecond: 10,
  ...over,
});

describe('discovery scope policy', () => {
  it('accepts a bounded range inside an allowed segment', () => {
    expect(validateDiscoveryScope(scope(), segments)).toEqual({ ok: true, targetCount: 14 });
  });
  it('refuses segments that disallow active discovery, public ranges and public flags', () => {
    const r1 = validateDiscoveryScope(scope({ includeCidrs: ['10.99.1.0/24'] }), segments);
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.reasons.join()).toMatch(/does not|not inside/);
    expect(validateDiscoveryScope(scope({ includeCidrs: ['8.8.8.0/24'] }), segments).ok).toBe(
      false,
    );
    expect(validateDiscoveryScope(scope({ allowPublicAddresses: true }), segments).ok).toBe(false);
    expect(
      validateDiscoveryScope(scope({ includeCidrs: [], includeAddresses: ['10.20.1.1'] }), segments)
        .ok,
    ).toBe(true);
    expect(
      validateDiscoveryScope(scope({ includeCidrs: [], includeAddresses: ['10.99.1.1'] }), segments)
        .ok,
    ).toBe(false);
  });
  it('refuses oversized scopes, intrusive techniques, excessive rates and IPv6 ranges', () => {
    expect(validateDiscoveryScope(scope({ includeCidrs: ['10.20.0.0/16'] }), segments).ok).toBe(
      false,
    ); // 65k targets
    expect(
      validateDiscoveryScope(scope({ allowedTechniques: ['vulnerability_scan'] }), segments).ok,
    ).toBe(false);
    expect(validateDiscoveryScope(scope({ maxRequestsPerSecond: 500 }), segments).ok).toBe(false);
    expect(validateDiscoveryScope(scope({ maxConcurrency: 64 }), segments).ok).toBe(false);
    expect(
      validateDiscoveryScope(scope({ includeCidrs: ['fd00::/120'] }), [
        { id: 'v6', cidr: 'fd00::/64', activeDiscoveryAllowed: true },
      ]).ok,
    ).toBe(false);
  });
  it('expands host addresses, skips network/broadcast and honours exclusions', () => {
    const t = expandTargets(scope());
    expect(t).toHaveLength(13); // 16 - network - broadcast - 1 excluded
    expect(t).not.toContain('10.20.5.0');
    expect(t).not.toContain('10.20.5.15');
    expect(t).not.toContain('10.20.5.3');
    expect(expandTargets(scope({ includeCidrs: ['10.20.5.1/32'] }))).toEqual(['10.20.5.1']);
    expect(expandTargets(scope({ includeCidrs: ['10.20.5.0/31'] }))).toEqual([
      '10.20.5.0',
      '10.20.5.1',
    ]);
    expect(expandTargets(scope({ includeCidrs: ['10.20.0.0/16'] }), 100)).toHaveLength(100);
  });
  it('cidrWithin is strict containment', () => {
    expect(cidrWithin('10.20.5.0/28', '10.20.0.0/16')).toBe(true);
    expect(cidrWithin('10.20.0.0/16', '10.20.5.0/28')).toBe(false);
    expect(cidrWithin('10.21.0.0/24', '10.20.0.0/16')).toBe(false);
  });
});
