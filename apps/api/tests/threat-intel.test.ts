import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import {
  ImportIndicatorsResponse,
  IndicatorMatch,
  IndicatorRecord,
  IngestReport,
  ThreatIntelStats,
} from '@noc/shared';
import {
  authed,
  createHarness,
  createUser,
  jsonOf,
  login,
  loginAdmin,
  resetDatabase,
  seedAdmin,
  type Harness,
} from './helpers';

let h: Harness;
let admin: { token: string };
let blue: string; // blue_team_engineer: threat_intel.read + manage
let analyst: string; // soc_analyst: threat_intel.read only
let noc: string; // noc_operator: neither
let cred: string;
const PW = 'threat-intel-password-long-enough';

const post = (path: string, token: string, body?: unknown) =>
  h.app.request(path, {
    method: 'POST',
    headers: authed(token),
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });
const postEve = (body: string) =>
  h.app.request('/api/v1/ingest/suricata/eve', {
    method: 'POST',
    headers: { 'content-type': 'application/x-ndjson', 'x-sensor-credential': cred },
    body,
  });

async function enrol(name: string) {
  const id = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name,
        kind: 'suricata',
        site: null,
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    )
  ).id as string;
  const { token } = await jsonOf(await post(`/api/v1/sensors/${id}/enrolment-token`, admin.token));
  const c = (
    await jsonOf(
      await h.app.request('/api/v1/agents/enrol', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          enrolmentToken: token,
          hostname: name,
          platform: { os: 'Ubuntu', osVersion: '24.04', kernel: '6.8', arch: 'x86_64' },
          agentVersion: '0.1.0',
        }),
      }),
    )
  ).credential as string;
  await h.handle.db.execute(sql`update sensors set enabled = true where id = ${id}`);
  return { id, cred: c };
}

const at = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString();
const base = (s: number, over: Record<string, unknown>) =>
  JSON.stringify({ timestamp: at(s), flow_id: 1000 + s, proto: 'TCP', ...over });
const dnsLine = (s: number, rrname: string) =>
  base(s, {
    event_type: 'dns',
    src_ip: '10.20.5.9',
    src_port: 51000,
    dest_ip: '10.20.0.53',
    dest_port: 53,
    proto: 'UDP',
    dns: { type: 'query', id: 1, rrname, rrtype: 'A', tx_id: 0 },
  });
const flowLine = (s: number, src: string, dst: string) =>
  base(s, {
    event_type: 'flow',
    src_ip: src,
    src_port: 44000,
    dest_ip: dst,
    dest_port: 443,
    flow: {
      pkts_toserver: 3,
      pkts_toclient: 2,
      bytes_toserver: 300,
      bytes_toclient: 200,
      start: at(s),
    },
  });
const httpLine = (s: number, hostname: string, url: string) =>
  base(s, {
    event_type: 'http',
    src_ip: '10.20.5.10',
    src_port: 45000,
    dest_ip: '192.0.2.80',
    dest_port: 80,
    http: { hostname, url, http_method: 'GET', status: 200 },
  });

const FEED = {
  indicators: [
    { type: 'ipv4', value: '203.0.113.9', severity: 'high', confidence: 90, tags: ['c2'] },
    { type: 'domain', value: 'evil.example', severity: 'critical', confidence: 80 },
    { type: 'cidr', value: '198.51.100.0/24', severity: 'medium', confidence: 40 },
    { type: 'url', value: 'http://bad.example/login/', severity: 'high' },
    { type: 'sha256', value: 'a'.repeat(64) },
  ],
};

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table security_events, sensors, threat_indicators cascade`,
  );
  h.limiter.reset();
  h.threatIntel.invalidate();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['blue@test.local', 'blue_team_engineer'],
    ['analyst@test.local', 'soc_analyst'],
    ['noc@test.local', 'noc_operator'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [blue, analyst, noc] = (await Promise.all(
    ['blue', 'analyst', 'noc'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string];
  cred = (await enrol('ids-edge-1')).cred;
});

describe('threat intelligence', () => {
  it('imports indicators under threat_intel.manage, merges by (type, value), and reports honestly', async () => {
    expect(
      (
        await post('/api/v1/threat-intel/indicators/import', analyst, {
          format: 'noc',
          source: 'x',
          content: '[]',
        })
      ).status,
    ).toBe(403);
    expect((await get('/api/v1/threat-intel/stats', noc)).status).toBe(403);
    const empty = ThreatIntelStats.parse(
      await jsonOf(await get('/api/v1/threat-intel/stats', analyst)),
    );
    expect(empty).toMatchObject({
      total: 0,
      active: 0,
      sources: [],
      lastImportAt: null,
      matches24h: 0,
      lastMatchAt: null,
    });
    const status0 = await jsonOf(await get('/api/v1/platform/status', admin.token));
    expect(
      status0.capabilities.find((c: { id: string }) => c.id === 'threat_intel.indicators').state,
    ).toBe('not_configured');

    const bad = await post('/api/v1/threat-intel/indicators/import', blue, {
      format: 'noc',
      source: 'feed-a',
      content: '{',
    });
    expect(bad.status).toBe(422);
    const r1 = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'noc',
          source: 'feed-a',
          content: JSON.stringify({
            indicators: [...FEED.indicators, { type: 'ipv4', value: '300.1.1.1' }],
          }),
        }),
      ),
    );
    expect(r1).toMatchObject({
      parsed: 5,
      imported: 5,
      updated: 0,
      unchanged: 0,
      revoked: 0,
      retroMatches: 0,
      errorCount: 1,
    });
    expect(r1.errors[0]).toContain('invalid ipv4');

    // Same feed again: nothing changes. A second feed re-asserting two indicators updates both
    // (source, severity, tag) but never lowers a confidence it does not state.
    const r2 = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'noc',
          source: 'feed-a',
          content: JSON.stringify(FEED),
        }),
      ),
    );
    expect(r2).toMatchObject({ imported: 0, updated: 0, unchanged: 5 });
    const r3 = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'csv',
          source: 'feed-b',
          content:
            'type,value,severity,tags\ncidr,198.51.100.0/24,high,scanner\nipv4,203.0.113.9,high,c2',
        }),
      ),
    );
    expect(r3).toMatchObject({ parsed: 2, imported: 0, updated: 2, unchanged: 0 });

    const list = await jsonOf(await get('/api/v1/threat-intel/indicators?type=cidr', analyst));
    expect(list.total).toBe(1);
    const cidr = IndicatorRecord.parse(list.items[0]);
    expect(cidr).toMatchObject({
      type: 'cidr',
      value: '198.51.100.0/24',
      severity: 'high',
      confidence: 40,
      source: 'feed-b',
      tags: ['scanner'],
      matchCount: 0,
    });
    const ip = (await jsonOf(await get('/api/v1/threat-intel/indicators?type=ipv4', analyst)))
      .items[0] as IndicatorRecord;
    expect(ip).toMatchObject({ confidence: 90, source: 'feed-b', tags: ['c2'] });
    const search = await jsonOf(await get('/api/v1/threat-intel/indicators?q=evil', analyst));
    expect(search.items.map((i: { value: string }) => i.value)).toEqual(['evil.example']);

    const stats = ThreatIntelStats.parse(
      await jsonOf(await get('/api/v1/threat-intel/stats', analyst)),
    );
    expect(stats).toMatchObject({
      total: 5,
      active: 5,
      expired: 0,
      revoked: 0,
      byType: { ipv4: 1, domain: 1, cidr: 1, url: 1, sha256: 1 },
    });
    expect(stats.sources.map((s) => [s.source, s.active])).toEqual([
      ['feed-b', 2],
      ['feed-a', 3],
    ]);
    const status1 = await jsonOf(await get('/api/v1/platform/status', admin.token));
    const cap = status1.capabilities.find(
      (c: { id: string }) => c.id === 'threat_intel.indicators',
    );
    expect(cap.state).toBe('available');
    expect(cap.reason).toContain('5 active indicator(s) from 2 source(s)');

    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    expect(
      (audit.items as Array<{ action: string }>).filter((a) => a.action === 'threat_intel.import'),
    ).toHaveLength(3);
  });

  it('matches indicators inline on ingest, raises de-duplicated alerts and records every sighting once', async () => {
    await post('/api/v1/threat-intel/indicators/import', blue, {
      format: 'noc',
      source: 'feed-a',
      content: JSON.stringify(FEED),
    });
    const body = [
      dnsLine(50, 'cdn.evil.example.'), // subdomain of a domain indicator
      flowLine(40, '10.20.5.9', '203.0.113.9'), // exact ipv4
      flowLine(30, '198.51.100.7', '10.20.0.2'), // inside the CIDR
      httpLine(20, 'bad.example', '/login/'), // URL indicator (scheme and trailing slash ignored)
      flowLine(10, '10.20.5.9', '10.20.0.2'), // clean
    ].join('\n');
    const report = IngestReport.parse(await jsonOf(await postEve(body)));
    expect(report).toMatchObject({
      accepted: 5,
      rejected: 0,
      indicatorMatches: 4,
      alertsCreated: 4,
      alertsUpdated: 0,
    });

    const matches = (await jsonOf(await get('/api/v1/threat-intel/matches', analyst))).items.map(
      (m: unknown) => IndicatorMatch.parse(m),
    );
    expect(
      matches.map((m: IndicatorMatch) => [m.type, m.matchedField, m.matchedValue, m.severity]),
    ).toEqual([
      ['url', 'http.url', 'bad.example/login', 'high'],
      ['cidr', 'src_ip', '198.51.100.7', 'medium'],
      ['ipv4', 'dst_ip', '203.0.113.9', 'high'],
      ['domain', 'dns.query', 'cdn.evil.example', 'critical'],
    ]);
    expect(matches.every((m: IndicatorMatch) => m.alertId !== null && m.eventId)).toBe(true);
    expect((await get('/api/v1/threat-intel/matches', noc)).status).toBe(403);

    const alerts = (await jsonOf(await get('/api/v1/alerts?limit=50', analyst))).items as Array<{
      title: string;
      severity: string;
      confidence: string;
      occurrenceCount: number;
      ruleRef?: string | null;
    }>;
    const ti = alerts.filter((a) => a.title.startsWith('Threat intel match'));
    expect(ti).toHaveLength(4);
    expect(ti.find((a) => a.title.includes('203.0.113.9'))).toMatchObject({
      severity: 'high',
      confidence: 'high',
      occurrenceCount: 1,
    });
    expect(ti.find((a) => a.title.includes('198.51.100.0/24'))).toMatchObject({
      severity: 'medium',
      confidence: 'medium',
    });

    // Same batch again: duplicates, no new matches, alerts untouched.
    const again = IngestReport.parse(await jsonOf(await postEve(body)));
    expect(again).toMatchObject({
      accepted: 0,
      duplicates: 5,
      indicatorMatches: 0,
      alertsCreated: 0,
      alertsUpdated: 0,
    });
    // A new sighting of the same indicator and tuple bumps the open alert instead of opening another.
    const more = IngestReport.parse(
      await jsonOf(await postEve(flowLine(5, '10.20.5.9', '203.0.113.9'))),
    );
    expect(more).toMatchObject({
      accepted: 1,
      indicatorMatches: 1,
      alertsCreated: 0,
      alertsUpdated: 1,
    });
    const after = (await jsonOf(await get('/api/v1/alerts?limit=50', analyst))).items as Array<{
      title: string;
      occurrenceCount: number;
    }>;
    expect(after.find((a) => a.title.includes('203.0.113.9'))?.occurrenceCount).toBe(2);

    const stats = ThreatIntelStats.parse(
      await jsonOf(await get('/api/v1/threat-intel/stats', analyst)),
    );
    expect(stats.matches24h).toBe(5);
    expect(stats.lastMatchAt).not.toBeNull();
    const ind = (await jsonOf(await get('/api/v1/threat-intel/indicators?type=ipv4', analyst)))
      .items[0] as IndicatorRecord;
    expect(ind.matchCount).toBe(2);
    expect(ind.lastMatchedAt).not.toBeNull();
    const status = await jsonOf(await get('/api/v1/platform/status', admin.token));
    expect(
      status.capabilities.find((c: { id: string }) => c.id === 'threat_intel.indicators').reason,
    ).toContain('5 match(es) in 24 h');
  });

  it('re-reads recent events when indicators arrive, and stops matching revoked ones', async () => {
    const stored = IngestReport.parse(
      await jsonOf(
        await postEve(
          [flowLine(120, '10.20.5.9', '203.0.113.9'), dnsLine(110, 'evil.example')].join('\n'),
        ),
      ),
    );
    expect(stored).toMatchObject({ accepted: 2, indicatorMatches: 0, alertsCreated: 0 });

    const r = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'noc',
          source: 'feed-a',
          content: JSON.stringify(FEED),
        }),
      ),
    );
    expect(r).toMatchObject({ imported: 5, retroMatches: 2, retroWindowHours: 24 });
    const alerts = (await jsonOf(await get('/api/v1/alerts?limit=50', analyst))).items as Array<{
      title: string;
    }>;
    expect(alerts.filter((a) => a.title.startsWith('Threat intel match'))).toHaveLength(2);
    // Unchanged re-import touches nothing, so nothing is re-read; the same sightings are not duplicated.
    const r2 = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'noc',
          source: 'feed-a',
          content: JSON.stringify(FEED),
        }),
      ),
    );
    expect(r2).toMatchObject({ unchanged: 5, retroMatches: 0 });
    expect((await jsonOf(await get('/api/v1/threat-intel/matches', analyst))).items).toHaveLength(
      2,
    );

    const ip = (await jsonOf(await get('/api/v1/threat-intel/indicators?type=ipv4', analyst)))
      .items[0] as IndicatorRecord;
    expect((await post(`/api/v1/threat-intel/indicators/${ip.id}/revoke`, analyst)).status).toBe(
      403,
    );
    const revoked = IndicatorRecord.parse(
      await jsonOf(await post(`/api/v1/threat-intel/indicators/${ip.id}/revoke`, blue)),
    );
    expect(revoked.revoked).toBe(true);
    expect(
      (
        await post(
          '/api/v1/threat-intel/indicators/00000000-0000-4000-8000-000000000000/revoke',
          blue,
        )
      ).status,
    ).toBe(404);
    const after = IngestReport.parse(
      await jsonOf(await postEve(flowLine(3, '10.20.5.11', '203.0.113.9'))),
    );
    expect(after).toMatchObject({ accepted: 1, indicatorMatches: 0, alertsCreated: 0 });
    expect(
      (await jsonOf(await get('/api/v1/threat-intel/indicators?type=ipv4', analyst))).total,
    ).toBe(0);
    expect(
      (
        await jsonOf(
          await get('/api/v1/threat-intel/indicators?type=ipv4&includeInactive=true', analyst),
        )
      ).total,
    ).toBe(1);
    const stats = ThreatIntelStats.parse(
      await jsonOf(await get('/api/v1/threat-intel/stats', analyst)),
    );
    expect(stats).toMatchObject({ total: 5, active: 4, revoked: 1 });
    // A feed that explicitly revokes an indicator is honoured; absence from a feed never revokes.
    const r3 = ImportIndicatorsResponse.parse(
      await jsonOf(
        await post('/api/v1/threat-intel/indicators/import', blue, {
          format: 'noc',
          source: 'feed-a',
          content: JSON.stringify({
            indicators: [{ type: 'domain', value: 'evil.example', revoked: true }],
          }),
        }),
      ),
    );
    expect(r3).toMatchObject({ revoked: 1, updated: 0, retroMatches: 0 });
    expect((await jsonOf(await get('/api/v1/threat-intel/stats', analyst))).active).toBe(3);
  });
});
