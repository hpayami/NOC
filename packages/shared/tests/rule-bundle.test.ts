import { describe, expect, it } from 'vitest';
import {
  bundleEngineFor,
  bundleManifest,
  ruleTargetsSite,
  selectBundleRules,
  type BundleCandidate,
} from '../src';

const rule = (over: Partial<BundleCandidate>): BundleCandidate => ({
  id: 'r',
  source: 'custom',
  externalId: '1:9000001',
  revision: 1,
  lifecycle: 'deployed',
  enabled: true,
  sites: [],
  contentSha256: 'a'.repeat(64),
  content: 'alert tcp any any -> any any (msg:"x"; sid:9000001; rev:1;)',
  ...over,
});

describe('rule bundles', () => {
  it('maps sensor kinds to engines and targets rules by site', () => {
    expect(bundleEngineFor('suricata')).toBe('suricata');
    expect(bundleEngineFor('zeek')).toBe('zeek');
    expect(bundleEngineFor('endpoint_agent')).toBeNull();
    expect(ruleTargetsSite([], null)).toBe(true);
    expect(ruleTargetsSite([], 'dc1')).toBe(true);
    expect(ruleTargetsSite(['dc1'], 'dc1')).toBe(true);
    expect(ruleTargetsSite(['dc1'], 'branch')).toBe(false);
    expect(ruleTargetsSite(['dc1'], null)).toBe(false); // a site-less sensor never gets targeted rules
  });

  it('selects only deployed, enabled, engine-matching, site-matching rules in a stable order', () => {
    const rules = [
      rule({ id: 'z', source: 'zeek_script', externalId: 'scan.zeek' }),
      rule({ id: 'draft', lifecycle: 'validated' }),
      rule({ id: 'off', enabled: false, externalId: '1:9000002' }),
      rule({ id: 'nocontent', content: null, externalId: '1:9000003' }),
      rule({ id: 'branch-only', sites: ['branch'], externalId: '1:9000004' }),
      rule({ id: 'dc-only', sites: ['dc1', 'dc2'], externalId: '1:9000005' }),
      rule({ id: 'everywhere', source: 'et_open', externalId: '1:2001219', revision: 20 }),
      rule({ id: 'everywhere-older', source: 'et_open', externalId: '1:2001219', revision: 19 }),
    ];
    expect(selectBundleRules(rules, { kind: 'suricata', site: 'dc1' }).map((r) => r.id)).toEqual([
      'dc-only',
      'everywhere-older',
      'everywhere',
    ]);
    expect(selectBundleRules(rules, { kind: 'suricata', site: null }).map((r) => r.id)).toEqual([
      'everywhere-older',
      'everywhere',
    ]);
    expect(selectBundleRules(rules, { kind: 'zeek', site: 'dc1' }).map((r) => r.id)).toEqual(['z']);
    expect(selectBundleRules(rules, { kind: 'endpoint_agent', site: 'dc1' })).toEqual([]);
  });

  it('produces a manifest that changes with membership, revision or content and nothing else', () => {
    const a = rule({});
    const m1 = bundleManifest([a]);
    expect(m1).toBe(`custom:1:9000001:1:${'a'.repeat(64)}\n`);
    expect(bundleManifest([{ ...a, revision: 2 }])).not.toBe(m1);
    expect(bundleManifest([{ ...a, contentSha256: 'b'.repeat(64) }])).not.toBe(m1);
    const renamed: BundleCandidate = { ...a, id: 'other-id' };
    expect(bundleManifest([renamed])).toBe(m1); // registry id is not part of the digest
    expect(bundleManifest([])).toBe('\n');
  });
});
