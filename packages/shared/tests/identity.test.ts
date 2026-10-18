import { describe, expect, it } from 'vitest';
import { resolveAssetIdentity, type CandidateAsset } from '../src';

const cand = (id: string, over: Partial<CandidateAsset> = {}): CandidateAsset => ({
  id,
  macAddresses: [],
  ipAddresses: [],
  hostnames: [],
  agentId: null,
  cloudInstanceId: null,
  segmentId: null,
  ...over,
});

describe('asset identity resolution', () => {
  it('creates when there are no candidates', () => {
    expect(
      resolveAssetIdentity(
        { macAddresses: ['aa:bb:cc:dd:ee:01'], ipAddresses: ['10.0.0.1'], hostnames: [] },
        [],
      ),
    ).toMatchObject({
      action: 'create',
      reason: 'no_candidates',
    });
  });

  it('never merges on a shared IP address alone', () => {
    const existing = cand('a', { macAddresses: ['aa:bb:cc:dd:ee:01'], ipAddresses: ['10.0.0.1'] });
    const r = resolveAssetIdentity(
      { macAddresses: ['aa:bb:cc:dd:ee:02'], ipAddresses: ['10.0.0.1'], hostnames: [] },
      [existing],
    );
    expect(r).toMatchObject({ action: 'create', reason: 'no_stable_identifier_match' });
  });

  it('re-attaches an address-only observation to the single current holder of the address', () => {
    const owner = cand('a', { macAddresses: ['aa:bb:cc:dd:ee:01'], ipAddresses: ['10.0.0.1'] });
    expect(
      resolveAssetIdentity({ macAddresses: [], ipAddresses: ['10.0.0.1'], hostnames: [] }, [owner]),
    ).toMatchObject({ action: 'match', assetId: 'a', reason: 'ip_sole_owner', confidence: 0.55 });
    // Two holders (DHCP reuse, stale interface): ambiguous, nothing merged.
    expect(
      resolveAssetIdentity({ macAddresses: [], ipAddresses: ['10.0.0.1'], hostnames: [] }, [
        owner,
        cand('b', { ipAddresses: ['10.0.0.1'] }),
      ]),
    ).toMatchObject({ action: 'ambiguous', reason: 'ip_sole_owner', candidateIds: ['a', 'b'] });
    // Any stable identifier disables the address tier: a different MAC on the same IP is a new device.
    expect(
      resolveAssetIdentity(
        { macAddresses: ['aa:bb:cc:dd:ee:09'], ipAddresses: ['10.0.0.1'], hostnames: [] },
        [owner],
      ),
    ).toMatchObject({ action: 'create', reason: 'no_stable_identifier_match' });
    expect(
      resolveAssetIdentity({ macAddresses: [], ipAddresses: ['10.0.0.1'], hostnames: ['x'] }, [
        owner,
      ]),
    ).toMatchObject({ action: 'create' });
  });

  it('matches on MAC overlap regardless of case and IP change', () => {
    const existing = cand('a', { macAddresses: ['aa:bb:cc:dd:ee:01'], ipAddresses: ['10.0.0.1'] });
    const r = resolveAssetIdentity(
      { macAddresses: ['AA:BB:CC:DD:EE:01'], ipAddresses: ['10.0.0.99'], hostnames: [] },
      [existing],
    );
    expect(r).toMatchObject({
      action: 'match',
      assetId: 'a',
      reason: 'mac_overlap',
      conflicts: [],
    });
  });

  it('prefers the agent id over MACs and records the MAC conflict', () => {
    const byMac = cand('mac-asset', { macAddresses: ['aa:bb:cc:dd:ee:01'] });
    const byAgent = cand('agent-asset', {
      agentId: 'agent-1',
      macAddresses: ['11:22:33:44:55:66'],
    });
    const r = resolveAssetIdentity(
      { agentId: 'agent-1', macAddresses: ['aa:bb:cc:dd:ee:01'], ipAddresses: [], hostnames: [] },
      [byMac, byAgent],
    );
    expect(r).toMatchObject({
      action: 'match',
      assetId: 'agent-asset',
      reason: 'agent_id',
      confidence: 0.95,
    });
    if (r.action === 'match') expect(r.conflicts).toContain('mac_set_disjoint');
  });

  it('matches hostname only inside the same segment', () => {
    const existing = cand('a', { hostnames: ['core-sw-01'], segmentId: 'seg-1' });
    expect(
      resolveAssetIdentity(
        { hostnames: ['CORE-SW-01'], segmentId: 'seg-1', macAddresses: [], ipAddresses: [] },
        [existing],
      ),
    ).toMatchObject({
      action: 'match',
      reason: 'hostname_segment',
      confidence: 0.6,
    });
    expect(
      resolveAssetIdentity(
        { hostnames: ['core-sw-01'], segmentId: 'seg-2', macAddresses: [], ipAddresses: [] },
        [existing],
      ),
    ).toMatchObject({ action: 'create' });
    expect(
      resolveAssetIdentity(
        { hostnames: ['core-sw-01'], segmentId: null, macAddresses: [], ipAddresses: [] },
        [existing],
      ),
    ).toMatchObject({ action: 'create' });
  });

  it('reports ambiguity instead of merging when several assets match on one tier', () => {
    const a = cand('a', { macAddresses: ['aa:bb:cc:dd:ee:01'] });
    const b = cand('b', { macAddresses: ['aa:bb:cc:dd:ee:02'] });
    const r = resolveAssetIdentity(
      { macAddresses: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'], ipAddresses: [], hostnames: [] },
      [a, b],
    );
    expect(r).toEqual({ action: 'ambiguous', reason: 'mac_overlap', candidateIds: ['a', 'b'] });
  });

  it('records hostname and segment disagreements on a MAC match', () => {
    const existing = cand('a', {
      macAddresses: ['aa:bb:cc:dd:ee:01'],
      hostnames: ['old-name'],
      segmentId: 'seg-1',
    });
    const r = resolveAssetIdentity(
      {
        macAddresses: ['aa:bb:cc:dd:ee:01'],
        hostnames: ['new-name'],
        segmentId: 'seg-2',
        ipAddresses: [],
      },
      [existing],
    );
    expect(r.action).toBe('match');
    if (r.action === 'match')
      expect(r.conflicts.sort()).toEqual(['hostname_mismatch', 'segment_mismatch']);
  });
});
