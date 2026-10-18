import { describe, expect, it } from 'vitest';
import {
  IndicatorIndex,
  extractObservables,
  indicatorConfidence,
  normalizeIndicatorValue,
  parseIndicatorFeed,
  parseStixPattern,
  splitCsvLine,
} from '../src';

const opts = { source: 'unit-feed', defaultSeverity: 'medium' as const };

describe('indicator normalisation', () => {
  it('canonicalises values per type and rejects invalid ones', () => {
    expect(normalizeIndicatorValue('ipv4', ' 10.0.0.1 ')).toBe('10.0.0.1');
    expect(normalizeIndicatorValue('ipv4', '10.0.0.256')).toBeNull();
    expect(normalizeIndicatorValue('ipv6', '2001:DB8::1')).toBe('2001:db8:0:0:0:0:0:1');
    expect(normalizeIndicatorValue('cidr', '10.1.0.0/16')).toBe('10.1.0.0/16');
    expect(normalizeIndicatorValue('cidr', '10.1.0.0/33')).toBeNull();
    expect(normalizeIndicatorValue('domain', 'Evil.Example.')).toBe('evil.example');
    expect(normalizeIndicatorValue('domain', 'not a domain')).toBeNull();
    expect(normalizeIndicatorValue('url', 'HTTPS://Evil.Example/Path/')).toBe('evil.example/Path');
    expect(normalizeIndicatorValue('url', 'http://bad host/x')).toBeNull();
    expect(normalizeIndicatorValue('sha256', 'A'.repeat(64))).toBe('a'.repeat(64));
    expect(normalizeIndicatorValue('sha256', 'a'.repeat(63))).toBeNull();
    expect(normalizeIndicatorValue('md5', 'f'.repeat(32))).toBe('f'.repeat(32));
    expect(indicatorConfidence(90)).toBe('high');
    expect(indicatorConfidence(50)).toBe('medium');
    expect(indicatorConfidence(10)).toBe('low');
  });
});

describe('parseIndicatorFeed', () => {
  it('reads the platform JSON format, de-duplicates and keeps the last assertion', () => {
    const r = parseIndicatorFeed(
      'noc',
      JSON.stringify({
        indicators: [
          { type: 'ipv4', value: '203.0.113.9', severity: 'high', confidence: 80, tags: ['c2'] },
          { type: 'domain', value: 'Evil.Example', expiresAt: '2027-01-01T00:00:00Z' },
          { type: 'ip', value: '203.0.113.0/24' },
          { type: 'sha256', value: 'zz' },
          { type: 'rumour', value: 'x' },
          'nope',
          { type: 'ipv4', value: '203.0.113.9', revoked: true },
        ],
      }),
      opts,
    );
    expect(r.errors).toEqual([
      '#3: invalid sha256 value "zz"',
      '#4: unknown indicator type "rumour"',
      '#5: not an object',
    ]);
    expect(r.records.map((x) => [x.type, x.value, x.severity, x.revoked])).toEqual([
      ['ipv4', '203.0.113.9', null, true],
      ['domain', 'evil.example', null, false],
      ['cidr', '203.0.113.0/24', null, false],
    ]);
    expect(r.records[1]!.expiresAt).toBe('2027-01-01T00:00:00.000Z');
    expect(parseIndicatorFeed('noc', '{', opts).errors).toEqual(['invalid JSON']);
  });

  it('reads CSV with a header and quoted fields', () => {
    expect(splitCsvLine('a,"b,c","d""e", f ')).toEqual(['a', 'b,c', 'd"e', 'f']);
    const csv = [
      '# exported by the SOC',
      'Type,Value,Severity,Confidence,Tags,Expires At,Description,Source',
      'domain,bad.example,critical,95,"phishing;c2",2030-01-01,"Phishing kit, observed",feed-x',
      'ipv4,198.51.100.7,,,,,,',
      'url,"http://bad.example/login/",high,70,,,,',
      'sha1,deadbeef,,,,,,',
    ].join('\n');
    const r = parseIndicatorFeed('csv', csv, opts);
    expect(r.errors).toEqual(['line 6: invalid sha1 value "deadbeef"']);
    expect(r.records).toHaveLength(3);
    expect(r.records[0]).toMatchObject({
      type: 'domain',
      value: 'bad.example',
      severity: 'critical',
      confidence: 95,
      tags: ['phishing', 'c2'],
      source: 'feed-x',
      description: 'Phishing kit, observed',
    });
    expect(r.records[1]).toMatchObject({ severity: null, confidence: null, source: 'unit-feed' });
    expect(r.records[2]).toMatchObject({ type: 'url', value: 'bad.example/login' });
    expect(parseIndicatorFeed('csv', 'value\n1', opts).errors).toEqual([
      'CSV header must include type and value',
    ]);
  });

  it('reads STIX 2.1 indicators with single comparisons and refuses compound patterns', () => {
    expect(parseStixPattern("[ipv4-addr:value = '1.2.3.4']")).toEqual({
      type: 'ipv4',
      value: '1.2.3.4',
    });
    expect(parseStixPattern("[file:hashes.'SHA-256' = 'ab']")).toEqual({
      type: 'sha256',
      value: 'ab',
    });
    expect(parseStixPattern("[url:value = 'http://x/it\\'s']")).toEqual({
      type: 'url',
      value: "http://x/it's",
    });
    expect(
      parseStixPattern("[ipv4-addr:value = '1.2.3.4' AND ipv4-addr:value = '5.6.7.8']"),
    ).toBeNull();
    expect(parseStixPattern("[process:name = 'x']")).toBeNull();
    const bundle = {
      type: 'bundle',
      objects: [
        { type: 'identity', id: 'identity--1', name: 'Partner CERT' },
        {
          type: 'indicator',
          id: 'indicator--1',
          pattern: "[domain-name:value = 'c2.example']",
          pattern_type: 'stix',
          confidence: 85,
          labels: ['malicious-activity', 'severity:high'],
          valid_until: '2030-06-01T00:00:00Z',
          created_by_ref: 'identity--1',
          name: 'C2 domain',
        },
        {
          type: 'indicator',
          id: 'indicator--2',
          pattern: "[ipv4-addr:value = '10.0.0.0/8' OR ipv4-addr:value = '1.1.1.1']",
        },
        { type: 'indicator', id: 'indicator--3', pattern: "[x:y = 'z']", pattern_type: 'sigma' },
        { type: 'malware', id: 'malware--1' },
      ],
    };
    const r = parseIndicatorFeed('stix2', JSON.stringify(bundle), opts);
    expect(r.errors).toEqual([
      'indicator--2: unsupported pattern (only single comparisons on ip/domain/url/file hashes)',
      'indicator--3: unsupported pattern_type sigma',
    ]);
    expect(r.records).toEqual([
      {
        type: 'domain',
        value: 'c2.example',
        source: 'unit-feed / Partner CERT',
        confidence: 85,
        severity: 'high',
        tags: ['malicious-activity', 'severity:high'],
        description: 'C2 domain',
        expiresAt: '2030-06-01T00:00:00.000Z',
        revoked: false,
      },
    ]);
    expect(parseIndicatorFeed('stix2', '{"objects":[]}', opts).errors).toEqual([
      'bundle contains no indicator objects',
    ]);
  });
});

describe('observables and matching', () => {
  const ind = (id: string, type: any, value: string) => ({
    id,
    type,
    value,
    source: 's',
    severity: 'high' as const,
    confidence: 80,
  });
  it('extracts canonical observables from what the normalisers keep', () => {
    const obs = extractObservables({
      srcIp: '10.0.0.5',
      dstIp: '2001:db8::9',
      engine: {
        dns: { rrname: 'Cdn.Evil.Example.' },
        tls: { sni: 'login.bad.example' },
        http: { hostname: 'bad.example', url: '/login/' },
        fileinfo: { sha256: 'A'.repeat(64), md5: 'b'.repeat(32) },
      },
    });
    expect(obs).toEqual([
      { field: 'src_ip', type: 'ipv4', value: '10.0.0.5' },
      { field: 'dst_ip', type: 'ipv6', value: '2001:db8:0:0:0:0:0:9' },
      { field: 'dns.query', type: 'domain', value: 'cdn.evil.example' },
      { field: 'tls.sni', type: 'domain', value: 'login.bad.example' },
      { field: 'http.hostname', type: 'domain', value: 'bad.example' },
      { field: 'http.url', type: 'url', value: 'bad.example/login' },
      { field: 'file.sha256', type: 'sha256', value: 'a'.repeat(64) },
      { field: 'file.md5', type: 'md5', value: 'b'.repeat(32) },
    ]);
    expect(extractObservables({ srcIp: null, dstIp: null, engine: {} })).toEqual([]);
  });

  it('matches exact values, subdomains and CIDR containment, once per indicator and field', () => {
    const idx = new IndicatorIndex([
      ind('a', 'domain', 'evil.example'),
      ind('b', 'cidr', '10.0.0.0/8'),
      ind('c', 'ipv4', '10.0.0.5'),
      ind('d', 'url', 'bad.example/login'),
      ind('e', 'sha256', 'a'.repeat(64)),
      ind('f', 'cidr', '2001:db8::/32'),
      ind('g', 'domain', 'example'),
    ]);
    expect(idx.size).toBe(7);
    const hits = idx.match(
      extractObservables({
        srcIp: '10.0.0.5',
        dstIp: '2001:db8::9',
        engine: {
          dns: { rrname: 'cdn.evil.example' },
          http: { hostname: 'bad.example', url: '/login' },
          fileinfo: { sha256: 'A'.repeat(64) },
        },
      }),
    );
    expect(hits.map((h) => [h.indicator.id, h.field, h.value])).toEqual([
      ['c', 'src_ip', '10.0.0.5'],
      ['b', 'src_ip', '10.0.0.5'],
      ['f', 'dst_ip', '2001:db8:0:0:0:0:0:9'],
      ['a', 'dns.query', 'cdn.evil.example'],
      ['d', 'http.url', 'bad.example/login'],
      ['e', 'file.sha256', 'a'.repeat(64)],
    ]);
    // A bare TLD-like indicator never matches by suffix; an unrelated event matches nothing.
    expect(
      idx.match(
        extractObservables({
          srcIp: '192.0.2.1',
          dstIp: null,
          engine: { dns: { rrname: 'good.example' } },
        }),
      ),
    ).toEqual([]);
  });
});
