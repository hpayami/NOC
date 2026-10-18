import { describe, expect, it } from 'vitest';
import {
  alertTitleFor,
  normalizeEveRecord,
  parseEveTimestamp,
  validateAlertTransition,
} from '../src';

const ctx = {
  sensorId: '3f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a11',
  eventId: '6f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a22',
  ingestTime: '2026-10-18T12:00:05.000Z',
};

const alertRecord = {
  timestamp: '2026-10-18T12:00:01.123456+0000',
  flow_id: 1234567890,
  in_iface: 'eth1',
  event_type: 'alert',
  src_ip: '10.20.5.9',
  src_port: 51515,
  dest_ip: '10.20.0.2',
  dest_port: 22,
  proto: 'TCP',
  community_id: '1:abc=',
  alert: {
    action: 'allowed',
    gid: 1,
    signature_id: 2001219,
    rev: 20,
    signature: 'ET SCAN Potential SSH Scan',
    category: 'Attempted Information Leak',
    severity: 2,
    metadata: { mitre_technique_id: ['T1046', 'bogus'], signature_severity: ['Minor'] },
  },
  payload: 'U1NILTIuMA==',
  payload_printable: 'SSH-2.0',
  packet: 'AAAA',
  app_proto: 'ssh',
};

describe('Suricata EVE normalizer', () => {
  it('parses Suricata timestamps with +0000 and microseconds', () => {
    expect(parseEveTimestamp('2026-10-18T12:00:01.123456+0000')).toBe('2026-10-18T12:00:01.123Z');
    expect(parseEveTimestamp('2026-10-18T14:30:00.000000+0230')).toBe('2026-10-18T12:00:00.000Z');
    expect(parseEveTimestamp('nope')).toBeNull();
  });

  it('maps an alert to a detection event with rule id, technique, correlation ids — and no payload', () => {
    const r = normalizeEveRecord(alertRecord, ctx);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const e = r.event;
    expect(e).toMatchObject({
      category: 'detection',
      type: 'alert',
      severity: 'medium',
      confidence: 'medium',
      srcIp: '10.20.5.9',
      dstPort: 22,
      protocol: 'tcp',
      ruleId: '1:2001219:20',
      threatClassification: ['T1046'],
    });
    expect(e.correlationIds).toEqual(['flow:1234567890', 'community:1:abc=']);
    expect(JSON.stringify(e)).not.toMatch(/payload|packet|U1NILTIuMA/);
    expect(alertTitleFor(e)).toBe('ET SCAN Potential SSH Scan');
  });

  it('maps severity levels and protocol records', () => {
    const sev = (s: number) => {
      const r = normalizeEveRecord(
        { ...alertRecord, alert: { ...alertRecord.alert, severity: s } },
        ctx,
      );
      return r.ok ? r.event.severity : 'x';
    };
    expect([sev(1), sev(2), sev(3), sev(4), sev(9)]).toEqual([
      'high',
      'medium',
      'low',
      'info',
      'info',
    ]);
    const dns = normalizeEveRecord(
      {
        timestamp: '2026-10-18T12:00:01.000000+0000',
        event_type: 'dns',
        src_ip: '10.0.0.1',
        dest_ip: '10.0.0.53',
        proto: 'UDP',
        dns: { type: 'query', rrname: 'example.test', rrtype: 'A' },
      },
      ctx,
    );
    expect(dns.ok && dns.event.category).toBe('dns');
    expect(dns.ok && dns.event.severity).toBe('info');
    expect(dns.ok && dns.event.confidence).toBe('high');
    expect(dns.ok && dns.event.ruleId).toBeNull();
    const tls = normalizeEveRecord(
      {
        timestamp: '2026-10-18T12:00:01.000000+0000',
        event_type: 'tls',
        src_ip: '10.0.0.1',
        dest_ip: '10.0.0.2',
        tls: { sni: 'example.test', ja3: { hash: 'abc' } },
      },
      ctx,
    );
    expect(tls.ok && (tls.event.engine.tls as { sni: string }).sni).toBe('example.test');
  });

  it('refuses malformed or unsupported records with a reason', () => {
    expect(normalizeEveRecord('not json', ctx)).toEqual({ ok: false, reason: 'not_an_object' });
    expect(normalizeEveRecord({ timestamp: '2026-10-18T12:00:01+0000' }, ctx)).toEqual({
      ok: false,
      reason: 'missing_event_type',
    });
    expect(
      normalizeEveRecord({ event_type: 'stats', timestamp: '2026-10-18T12:00:01+0000' }, ctx),
    ).toMatchObject({ ok: false, reason: 'unsupported_event_type:stats' });
    expect(normalizeEveRecord({ event_type: 'alert', timestamp: 'garbage' }, ctx)).toEqual({
      ok: false,
      reason: 'invalid_timestamp',
    });
    const bad = normalizeEveRecord({ ...alertRecord, src_ip: 'not-an-ip' }, ctx);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toMatch(/^schema:srcIp/);
  });
});

describe('alert triage state machine', () => {
  it('allows the common path and requires notes on dispositions', () => {
    expect(validateAlertTransition('new', 'acknowledge')).toMatchObject({
      ok: true,
      to: 'acknowledged',
    });
    expect(validateAlertTransition('acknowledged', 'investigate')).toMatchObject({
      ok: true,
      to: 'investigating',
    });
    expect(validateAlertTransition('investigating', 'resolve')).toMatchObject({ ok: false });
    expect(
      validateAlertTransition(
        'investigating',
        'resolve',
        'Blocked at firewall, confirmed benign scanner',
      ),
    ).toMatchObject({ ok: true, to: 'resolved' });
    expect(validateAlertTransition('new', 'false_positive', 'x')).toMatchObject({ ok: false });
  });
  it('blocks nonsense transitions and allows reopen only from closed/suppressed', () => {
    expect(validateAlertTransition('resolved', 'acknowledge').ok).toBe(false);
    expect(validateAlertTransition('resolved', 'reopen', 'recurred').ok).toBe(true);
    expect(validateAlertTransition('new', 'reopen', 'why').ok).toBe(false);
    expect(validateAlertTransition('suppressed', 'reopen', 'suppression lifted').ok).toBe(true);
  });
});
