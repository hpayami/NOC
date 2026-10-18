import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { IngestReport } from '@noc/shared';
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
let analyst: string;
let blue: string; // blue_team_engineer: detection_rules.change, events.ingest
let secadmin: string; // security_admin: detection_rules.deploy but not change
let suricata: { id: string; cred: string };
let zeek: { id: string; cred: string };
const PW = 'zeek-password-that-is-long-enough';

async function enrolSensor(name: string, kind: string) {
  const id = (
    await jsonOf(
      await h.app.request('/api/v1/sensors', {
        method: 'POST',
        headers: authed(admin.token),
        body: JSON.stringify({
          name,
          kind,
          site: 'dc1',
          monitoredSegmentIds: [],
          engineVersion: null,
        }),
      }),
    )
  ).id;
  const { token } = await jsonOf(
    await h.app.request(`/api/v1/sensors/${id}/enrolment-token`, {
      method: 'POST',
      headers: authed(admin.token),
    }),
  );
  const cred = (
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
  ).credential;
  return { id, cred };
}

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, security_events, alerts, sensors, sensor_health, detection_rules cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  await createUser(h, admin.token, {
    email: 'blue@test.local',
    password: PW,
    roles: ['blue_team_engineer'],
  });
  await createUser(h, admin.token, {
    email: 'sec@test.local',
    password: PW,
    roles: ['security_admin'],
  });
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken;
  secadmin = (await login(h, 'sec@test.local', PW)).body.accessToken;
  suricata = await enrolSensor('suricata-dc1', 'suricata');
  zeek = await enrolSensor('zeek-dc1', 'zeek');
});

const ndjson = (...lines: unknown[]) =>
  lines.map((l) => (typeof l === 'string' ? l : JSON.stringify(l))).join('\n') + '\n';
const post = (path: string, cred: string, body: string) =>
  h.app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-ndjson', 'x-sensor-credential': cred },
    body,
  });

const RULES = `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; classtype:attempted-recon; sid:2001219; rev:20; metadata:mitre_technique_id T1046, signature_severity Minor;)
#alert udp any any -> any 53 (msg:"ET DNS Query for .onion"; classtype:policy-violation; sid:2014169; rev:3; metadata:signature_severity Major;)
alert tcp any any -> any any (content:"no msg"; sid:9000002; rev:1;)
`;

describe('Zeek ingestion and cross-engine correlation', () => {
  it('normalizes conn/dns/notice, creates alerts for notices and correlates with Suricata by community id', async () => {
    const zeekBody = ndjson(
      {
        _path: 'conn',
        ts: 1792324800.5,
        uid: 'CAbc123',
        id: { orig_h: '10.20.5.9', orig_p: 51515, resp_h: '10.20.0.2', resp_p: 22 },
        proto: 'tcp',
        service: 'ssh',
        conn_state: 'SF',
        community_id: '1:same=',
      },
      {
        _path: 'dns',
        ts: 1792324801,
        uid: 'CDef456',
        id: { orig_h: '10.20.5.9', orig_p: 5353, resp_h: '10.20.0.53', resp_p: 53 },
        proto: 'udp',
        query: 'example.test',
        qtype_name: 'A',
      },
      {
        _path: 'notice',
        ts: 1792324802,
        uid: 'CAbc123',
        note: 'Scan::Port_Scan',
        msg: '10.20.5.9 scanned at least 15 unique ports',
        src: '10.20.5.9',
        dst: '10.20.0.2',
        p: 22,
      },
      { _path: 'capture_loss', ts: 1792324803, percent_lost: 0 },
      { _path: 'conn', ts: 'not-a-time', uid: 'X' },
    );
    const r = IngestReport.parse(
      await jsonOf(await post('/api/v1/ingest/zeek/logs', zeek.cred, zeekBody)),
    );
    expect(r).toMatchObject({ received: 5, accepted: 3, rejected: 2, alertsCreated: 1 });
    expect(r.rejections.map((x) => x.reason)).toEqual([
      'unsupported_path:capture_loss',
      'invalid_timestamp',
    ]);

    // Default path for file-based logs without _path.
    const r2 = IngestReport.parse(
      await jsonOf(
        await post(
          '/api/v1/ingest/zeek/logs?path=ssl',
          zeek.cred,
          ndjson({
            ts: 1792324804,
            uid: 'C9',
            id: { orig_h: '10.20.5.9', orig_p: 1, resp_h: '10.20.0.2', resp_p: 443 },
            server_name: 'example.test',
            version: 'TLSv13',
          }),
        ),
      ),
    );
    expect(r2.accepted).toBe(1);
    expect((await post('/api/v1/ingest/zeek/logs', suricata.cred, zeekBody)).status).toBe(409); // wrong engine kind

    const suricataLine = JSON.stringify({
      timestamp: '2026-10-18T12:00:00.600000+0000',
      flow_id: 777,
      event_type: 'alert',
      src_ip: '10.20.5.9',
      src_port: 51515,
      dest_ip: '10.20.0.2',
      dest_port: 22,
      proto: 'TCP',
      community_id: '1:same=',
      alert: {
        gid: 1,
        signature_id: 2001219,
        rev: 20,
        signature: 'ET SCAN Potential SSH Scan',
        severity: 2,
      },
    });
    expect(
      (await post('/api/v1/ingest/suricata/eve', suricata.cred, suricataLine + '\n')).status,
    ).toBe(202);

    const corr = await jsonOf(
      await h.app.request('/api/v1/events/correlated?correlationId=community:1:same=', {
        headers: authed(analyst),
      }),
    );
    expect(
      corr.items
        .map((e: { sourceProduct: string; type: string }) => `${e.sourceProduct}:${e.type}`)
        .sort(),
    ).toEqual(['suricata:alert', 'zeek:conn']);
    const byUid = await jsonOf(
      await h.app.request('/api/v1/events/correlated?correlationId=zeek:CAbc123', {
        headers: authed(analyst),
      }),
    );
    expect(byUid.items).toHaveLength(2); // conn + notice share the uid

    const queue = await jsonOf(
      await h.app.request('/api/v1/alerts?open=true', { headers: authed(analyst) }),
    );
    expect(
      queue.items
        .map((a: { sourceProduct: string; title: string }) => [a.sourceProduct, a.title])
        .sort(),
    ).toEqual([
      ['suricata', 'ET SCAN Potential SSH Scan'],
      ['zeek', '10.20.5.9 scanned at least 15 unique ports'],
    ]);
    const stats = await jsonOf(
      await h.app.request('/api/v1/events/stats', { headers: authed(analyst) }),
    );
    expect(
      stats.sensors.map((s: { kind: string; events: number }) => [s.kind, s.events]).sort(),
    ).toEqual([
      ['suricata', 1],
      ['zeek', 4],
    ]);
  });
});

describe('detection-rule registry', () => {
  it('imports idempotently with licence, tracks lifecycle, and links alerts to rules', async () => {
    expect(
      (
        await h.app.request('/api/v1/detection-rules/import', {
          method: 'POST',
          headers: authed(analyst),
          body: JSON.stringify({
            source: 'et_open',
            ruleSet: 'emerging-scan',
            license: 'BSD-2-Clause',
            content: RULES,
          }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await h.app.request('/api/v1/detection-rules/import', {
          method: 'POST',
          headers: authed(blue),
          body: JSON.stringify({ source: 'et_open', ruleSet: 'emerging-scan', content: RULES }),
        })
      ).status,
    ).toBe(400); // licence required
    const imp = await jsonOf(
      await h.app.request('/api/v1/detection-rules/import', {
        method: 'POST',
        headers: authed(blue),
        body: JSON.stringify({
          source: 'et_open',
          ruleSet: 'emerging-scan',
          license: 'BSD-2-Clause',
          content: RULES,
        }),
      }),
    );
    expect(imp).toMatchObject({ parsed: 2, imported: 2, updated: 0, unchanged: 0, errorCount: 1 });
    expect(imp.errors[0].message).toMatch(/missing msg/);
    const again = await jsonOf(
      await h.app.request('/api/v1/detection-rules/import', {
        method: 'POST',
        headers: authed(blue),
        body: JSON.stringify({
          source: 'et_open',
          ruleSet: 'emerging-scan',
          license: 'BSD-2-Clause',
          content: RULES,
        }),
      }),
    );
    expect(again).toMatchObject({ imported: 0, updated: 0, unchanged: 2 });

    const list = await jsonOf(
      await h.app.request('/api/v1/detection-rules?q=2001219', { headers: authed(analyst) }),
    );
    expect(list.items).toHaveLength(1);
    const rule = list.items[0];
    expect(rule).toMatchObject({
      externalId: '1:2001219',
      revision: 20,
      lifecycle: 'draft',
      severity: 'medium',
      attackTechniques: ['T1046'],
      enabled: true,
      classtype: 'attempted-recon',
      license: 'BSD-2-Clause',
    });
    const disabledRule = (
      await jsonOf(
        await h.app.request('/api/v1/detection-rules?q=1:2014169', { headers: authed(analyst) }),
      )
    ).items[0];
    expect(disabledRule).toMatchObject({ enabled: false, severity: 'high' });

    expect(
      (
        await h.app.request(`/api/v1/detection-rules/${rule.id}/validate`, {
          method: 'POST',
          headers: authed(secadmin),
        })
      ).status,
    ).toBe(403); // deploy-side role cannot change
    const validated = await jsonOf(
      await h.app.request(`/api/v1/detection-rules/${rule.id}/validate`, {
        method: 'POST',
        headers: authed(blue),
      }),
    );
    expect(validated.lifecycle).toBe('validated');
    expect(validated.validatedAt).toBeTruthy();
    const stats = await jsonOf(
      await h.app.request('/api/v1/detection-rules/stats', { headers: authed(analyst) }),
    );
    expect(stats).toMatchObject({ total: 2, enabled: 1, withTechniques: 1 });
    expect(stats.byLifecycle.validated).toBe(1);

    // An alert for a registered rule links to the registry entry (exact revision preferred).
    const line = JSON.stringify({
      timestamp: '2026-10-18T12:00:00.000000+0000',
      flow_id: 1,
      event_type: 'alert',
      src_ip: '10.20.5.9',
      dest_ip: '10.20.0.2',
      dest_port: 22,
      proto: 'TCP',
      alert: {
        gid: 1,
        signature_id: 2001219,
        rev: 20,
        signature: 'ET SCAN Potential SSH Scan',
        severity: 2,
      },
    });
    await post('/api/v1/ingest/suricata/eve', suricata.cred, line + '\n');
    const [a] = (await jsonOf(await h.app.request('/api/v1/alerts', { headers: authed(analyst) })))
      .items;
    expect(a.ruleId).toBe(rule.id);

    // Changed content under the same revision goes back to draft.
    const changed = RULES.replace('rev:20;', 'rev:20; reference:url,example.test;');
    const upd = await jsonOf(
      await h.app.request('/api/v1/detection-rules/import', {
        method: 'POST',
        headers: authed(blue),
        body: JSON.stringify({
          source: 'et_open',
          ruleSet: 'emerging-scan',
          license: 'BSD-2-Clause',
          content: changed,
        }),
      }),
    );
    expect(upd).toMatchObject({ updated: 1, unchanged: 1 });
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/detection-rules/${rule.id}`, { headers: authed(analyst) }),
        )
      ).lifecycle,
    ).toBe('draft');
  });
});

describe('live alert stream (SSE)', () => {
  it('pushes created/triaged events to authorized subscribers', async () => {
    expect((await h.app.request('/api/v1/alerts/stream')).status).toBe(401);
    const res = await h.app.request('/api/v1/alerts/stream', { headers: authed(analyst) });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/text\/event-stream/);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    const readUntil = async (pattern: RegExp, timeoutMs = 5000) => {
      const deadline = Date.now() + timeoutMs;
      while (!pattern.test(buffer)) {
        if (Date.now() > deadline)
          throw new Error(`timeout waiting for ${pattern}; buffer=${buffer}`);
        const { value, done } = await reader.read();
        if (done) throw new Error('stream closed');
        buffer += decoder.decode(value);
      }
    };
    await readUntil(/event: ready/);
    const line = JSON.stringify({
      timestamp: '2026-10-18T12:00:00.000000+0000',
      flow_id: 1,
      event_type: 'alert',
      src_ip: '10.20.5.9',
      dest_ip: '10.20.0.2',
      dest_port: 22,
      proto: 'TCP',
      alert: {
        gid: 1,
        signature_id: 2001219,
        rev: 20,
        signature: 'ET SCAN Potential SSH Scan',
        severity: 2,
      },
    });
    await post('/api/v1/ingest/suricata/eve', suricata.cred, line + '\n');
    await readUntil(/event: alert\ndata: \{"kind":"created"/);
    const [a] = (await jsonOf(await h.app.request('/api/v1/alerts', { headers: authed(analyst) })))
      .items;
    await h.app.request(`/api/v1/alerts/${a.id}`, {
      method: 'PATCH',
      headers: authed(analyst),
      body: JSON.stringify({ action: 'acknowledge' }),
    });
    await readUntil(/"kind":"triaged"/);
    await reader.cancel();
  });
});
