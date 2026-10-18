import { describe, expect, it } from 'vitest';
import {
  noticeSeverity,
  normalizeZeekRecord,
  parseSuricataRules,
  parseZeekTimestamp,
  ruleSeverity,
  ruleTechniques,
} from '../src';

const ctx = {
  sensorId: '3f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a11',
  eventId: '6f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a22',
  ingestTime: '2026-10-18T12:00:05.000Z',
};

describe('Zeek normalizer', () => {
  it('parses epoch and ISO timestamps', () => {
    expect(parseZeekTimestamp(1792324800.123456)).toBe('2026-10-18T12:00:00.123Z');
    expect(parseZeekTimestamp('2026-10-18T12:00:00.000Z')).toBe('2026-10-18T12:00:00.000Z');
    expect(parseZeekTimestamp('x')).toBeNull();
  });
  it('maps conn records with nested id and community id', () => {
    const r = normalizeZeekRecord(
      {
        _path: 'conn',
        ts: 1792324800.5,
        uid: 'CAbc123',
        id: { orig_h: '10.20.5.9', orig_p: 51515, resp_h: '10.20.0.2', resp_p: 22 },
        proto: 'tcp',
        service: 'ssh',
        duration: 3.2,
        orig_bytes: 300,
        resp_bytes: 1200,
        conn_state: 'SF',
        community_id: '1:abc=',
      },
      ctx,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event).toMatchObject({
      sourceProduct: 'zeek',
      category: 'network',
      type: 'conn',
      severity: 'info',
      confidence: 'high',
      srcIp: '10.20.5.9',
      dstPort: 22,
      protocol: 'tcp',
      ruleId: null,
    });
    expect(r.event.correlationIds).toEqual(['zeek:CAbc123', 'community:1:abc=']);
    expect(r.event.engine).toMatchObject({
      flow_id: 'CAbc123',
      zeek_path: 'conn',
      conn: { service: 'ssh', conn_state: 'SF' },
    });
  });
  it('uses the default path for file-based logs and flattened id fields', () => {
    const r = normalizeZeekRecord(
      {
        ts: 1792324800,
        uid: 'C1',
        'id.orig_h': '10.0.0.1',
        'id.orig_p': 1,
        'id.resp_h': '10.0.0.53',
        'id.resp_p': 53,
        proto: 'udp',
        query: 'example.test',
        qtype_name: 'A',
        answers: ['93.184.216.34'],
      },
      { ...ctx, defaultPath: 'dns' },
    );
    expect(r.ok && r.event.category).toBe('dns');
    expect(r.ok && (r.event.engine.dns as { query: string }).query).toBe('example.test');
    expect(normalizeZeekRecord({ ts: 1 }, ctx)).toEqual({ ok: false, reason: 'missing_path' });
    expect(normalizeZeekRecord({ ts: 1, _path: 'capture_loss' }, ctx)).toMatchObject({
      ok: false,
      reason: 'unsupported_path:capture_loss',
    });
  });
  it('turns notices into detections with severity by note', () => {
    const r = normalizeZeekRecord(
      {
        _path: 'notice',
        ts: 1792324800,
        uid: 'C2',
        note: 'Scan::Port_Scan',
        msg: '10.20.5.9 scanned at least 15 unique ports',
        src: '10.20.5.9',
        dst: '10.20.0.2',
        p: 445,
        actions: ['Notice::ACTION_LOG'],
      },
      ctx,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event).toMatchObject({
      category: 'detection',
      type: 'notice',
      severity: 'medium',
      confidence: 'medium',
      ruleId: 'zeek:Scan::Port_Scan',
      srcIp: '10.20.5.9',
      dstIp: '10.20.0.2',
      dstPort: 445,
    });
    expect(noticeSeverity('Intel::Notice')).toBe('high');
    expect(noticeSeverity('Weird::Activity')).toBe('low');
    expect(noticeSeverity(undefined)).toBe('low');
  });
  it('maps ssl to tls fields and keeps nothing unexpected', () => {
    const r = normalizeZeekRecord(
      {
        _path: 'ssl',
        ts: 1792324800,
        uid: 'C3',
        id: { orig_h: '10.0.0.1', orig_p: 1, resp_h: '10.0.0.2', resp_p: 443 },
        server_name: 'example.test',
        version: 'TLSv13',
        ja3: 'abcd',
        secret_blob: 'should-not-leak',
      },
      ctx,
    );
    expect(r.ok && r.event.category).toBe('tls');
    expect(JSON.stringify(r)).not.toMatch(/secret_blob|should-not-leak/);
  });
});

describe('Suricata rule parser', () => {
  const text = `# comment line
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; classtype:attempted-recon; sid:2001219; rev:20; metadata:created_at 2010_07_30, updated_at 2010_07_30, mitre_technique_id T1046, signature_severity Minor;)
#alert udp any any -> any 53 (msg:"ET DNS Query for .onion"; content:"|05|onion|00|"; classtype:policy-violation; sid:2014169; rev:3; metadata:signature_severity Major;)
alert http any any -> any any (msg:"Custom semicolon \\; in content"; content:"a\\;b"; sid:9000001; rev:1;)
this is garbage
alert tcp any any -> any any (content:"no msg"; sid:9000002; rev:1;)
alert tcp any any -> any any (msg:"no sid";)
`;
  it('parses enabled and disabled rules, metadata, references and escaped options', () => {
    const r = parseSuricataRules(text);
    expect(r.rules.map((x) => [x.sid, x.rev, x.enabled, x.classtype])).toEqual([
      [2001219, 20, true, 'attempted-recon'],
      [2014169, 3, false, 'policy-violation'],
      [9000001, 1, true, null],
    ]);
    expect(r.rules[0]!.metadata).toMatchObject({
      mitre_technique_id: ['T1046'],
      signature_severity: ['Minor'],
    });
    expect(r.rules[0]!.references).toEqual(['url,en.wikipedia.org/wiki/Brute_force_attack']);
    expect(r.rules[2]!.msg).toBe('Custom semicolon \\; in content');
    expect(r.errors).toEqual([
      { line: 5, message: 'unparseable rule header' },
      { line: 6, message: 'sid 9000002: missing msg' },
      { line: 7, message: 'missing or invalid sid' },
    ]);
  });
  it('derives severity and techniques', () => {
    const r = parseSuricataRules(text);
    expect(ruleSeverity(r.rules[0]!)).toBe('medium'); // Minor
    expect(ruleSeverity(r.rules[1]!)).toBe('high'); // Major
    expect(ruleSeverity(r.rules[2]!)).toBe('medium'); // no classtype
    expect(ruleSeverity({ classtype: 'trojan-activity', metadata: {} })).toBe('high');
    expect(ruleTechniques(r.rules[0]!)).toEqual(['T1046']);
  });
});
