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
let analyst: string; // soc_analyst: events.read, alerts.read, alerts.triage
let blue: string; // blue_team_engineer: events.ingest (replay)
let noc: string; // noc_operator: no event permissions
let sensorId: string;
let cred: string;
const PW = 'nids-password-that-is-long-enough';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, security_events, alerts, sensors, sensor_health cascade`,
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
    email: 'noc@test.local',
    password: PW,
    roles: ['noc_operator'],
  });
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken;
  noc = (await login(h, 'noc@test.local', PW)).body.accessToken;
  sensorId = (
    await jsonOf(
      await h.app.request('/api/v1/sensors', {
        method: 'POST',
        headers: authed(admin.token),
        body: JSON.stringify({
          name: 'suricata-dc1',
          kind: 'suricata',
          site: 'dc1',
          monitoredSegmentIds: [],
          engineVersion: '7.0.6',
        }),
      }),
    )
  ).id;
  const { token } = await jsonOf(
    await h.app.request(`/api/v1/sensors/${sensorId}/enrolment-token`, {
      method: 'POST',
      headers: authed(admin.token),
    }),
  );
  cred = (
    await jsonOf(
      await h.app.request('/api/v1/agents/enrol', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          enrolmentToken: token,
          hostname: 'suricata-dc1',
          platform: { os: 'Ubuntu', osVersion: '24.04', kernel: '6.8', arch: 'x86_64' },
          agentVersion: '0.1.0',
        }),
      }),
    )
  ).credential;
});

const ts = (s: number) => `2026-10-18T12:00:${String(s).padStart(2, '0')}.000000+0000`;
const alertLine = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    timestamp: ts(1),
    flow_id: 111,
    event_type: 'alert',
    src_ip: '10.20.5.9',
    src_port: 51515,
    dest_ip: '10.20.0.2',
    dest_port: 22,
    proto: 'TCP',
    alert: {
      action: 'allowed',
      gid: 1,
      signature_id: 2001219,
      rev: 20,
      signature: 'ET SCAN Potential SSH Scan',
      category: 'Attempted Information Leak',
      severity: 2,
      metadata: { mitre_technique_id: ['T1046'] },
    },
    payload_printable: 'SSH-2.0-OpenSSH',
    ...over,
  });
const ndjson = (...lines: string[]) => lines.join('\n') + '\n';
const postEve = (headers: Record<string, string>, body: string, qs = '') =>
  h.app.request(`/api/v1/ingest/suricata/eve${qs}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-ndjson', ...headers },
    body,
  });
const sensorHeaders = () => ({ 'x-sensor-credential': cred });

describe('Suricata EVE ingestion and alert queue', () => {
  it('accepts only sensor credentials or events.ingest replay, and only for engine sensors', async () => {
    expect((await postEve({}, alertLine())).status).toBe(401);
    expect((await postEve(authed(analyst), alertLine())).status).toBe(401);
    expect((await postEve(authed(blue), alertLine())).status).toBe(400); // replay needs sensorId
    expect((await postEve(authed(blue), alertLine(), `?sensorId=${sensorId}`)).status).toBe(202);
    const hostAgent = (
      await jsonOf(
        await h.app.request('/api/v1/sensors', {
          method: 'POST',
          headers: authed(admin.token),
          body: JSON.stringify({
            name: 'agent',
            kind: 'host_agent',
            site: null,
            monitoredSegmentIds: [],
            engineVersion: null,
          }),
        }),
      )
    ).id;
    expect((await postEve(authed(blue), alertLine(), `?sensorId=${hostAgent}`)).status).toBe(409);
  });

  it('normalizes, deduplicates, strips payloads, correlates assets and builds the alert queue', async () => {
    // Known asset for the destination address.
    await h.app.request('/api/v1/assets/observations', {
      method: 'POST',
      headers: authed(noc),
      body: JSON.stringify({
        source: 't',
        method: 'manual',
        observedAt: '2026-10-18T10:00:00Z',
        identifiers: {
          macAddresses: ['aa:bb:cc:00:00:02'],
          ipAddresses: ['10.20.0.2'],
          hostnames: ['core-sw-01'],
        },
        attributes: {},
      }),
    });
    const body = ndjson(
      alertLine(),
      alertLine(), // exact duplicate
      alertLine({ timestamp: ts(2), flow_id: 112 }), // same signature, second occurrence
      JSON.stringify({
        timestamp: ts(3),
        event_type: 'dns',
        src_ip: '10.20.5.9',
        dest_ip: '10.20.0.53',
        proto: 'UDP',
        dns: { type: 'query', rrname: 'example.test', rrtype: 'A' },
      }),
      JSON.stringify({ timestamp: ts(3), event_type: 'stats', stats: { uptime: 1 } }),
      'this is not json',
      JSON.stringify({
        timestamp: ts(4),
        event_type: 'flow',
        src_ip: '10.20.5.9',
        dest_ip: '10.20.0.2',
        proto: 'TCP',
        flow: { pkts_toserver: 3, bytes_toserver: 300 },
      }),
    );
    const r = await postEve(sensorHeaders(), body);
    expect(r.status).toBe(202);
    const report = IngestReport.parse(await jsonOf(r));
    expect(report).toMatchObject({
      received: 7,
      accepted: 4,
      duplicates: 1,
      rejected: 2,
      alertsCreated: 1,
      alertsUpdated: 1,
    });
    expect(report.rejections.map((x) => x.reason)).toEqual([
      'unsupported_event_type:stats',
      'invalid_json',
    ]);
    expect(report.maxEventLagSeconds).not.toBeNull(); // fixture times may be in the future relative to the clock; lag is clamped at 0

    const events = await jsonOf(
      await h.app.request('/api/v1/events?from=2026-10-18T00:00:00Z&to=2026-10-19T00:00:00Z', {
        headers: authed(analyst),
      }),
    );
    expect(events.items).toHaveLength(4);
    expect(JSON.stringify(events)).not.toMatch(/payload|OpenSSH/);
    const alertEvent = events.items.find(
      (e: { type: string; ruleId: string }) => e.type === 'alert',
    );
    expect(alertEvent.dstAssetId).toBeTruthy();
    expect(alertEvent.threatClassification).toEqual(['T1046']);

    const queue = await jsonOf(
      await h.app.request('/api/v1/alerts?open=true', { headers: authed(analyst) }),
    );
    expect(queue.items).toHaveLength(1);
    expect(queue.items[0]).toMatchObject({
      title: 'ET SCAN Potential SSH Scan',
      status: 'new',
      severity: 'medium',
      occurrenceCount: 2,
      sourceProduct: 'suricata',
    });
    expect(queue.items[0].assetId).toBe(alertEvent.dstAssetId);
    expect(queue.items[0].priorityScore).toBeGreaterThan(0);
    expect(queue.items[0].lastSeenAt).toBe('2026-10-18T12:00:02.000Z');

    const detail = await jsonOf(
      await h.app.request(`/api/v1/alerts/${queue.items[0].id}`, { headers: authed(analyst) }),
    );
    expect(detail.recentEvents).toHaveLength(2);
    expect(detail.alert.ruleRef).toBe('1:2001219:20');

    const stats = await jsonOf(
      await h.app.request('/api/v1/events/stats', { headers: authed(analyst) }),
    );
    expect(stats.byType).toEqual({ alert: 2, dns: 1, flow: 1 });
    expect(stats.sensors[0]).toMatchObject({ sensorId, events: 4 });
    expect(stats.sensors[0].lastEventAt).toBe('2026-10-18T12:00:04.000Z');

    // Re-sending the same batch is idempotent.
    const again = IngestReport.parse(await jsonOf(await postEve(sensorHeaders(), body)));
    expect(again).toMatchObject({ accepted: 0, duplicates: 5, alertsCreated: 0, alertsUpdated: 0 }); // 5 normalizable records, all already stored
  });

  it('enforces bounds: record cap, event range, and RBAC on reads', async () => {
    const big = Array.from({ length: 1001 }, (_, i) =>
      alertLine({ timestamp: ts(i % 60), flow_id: i }),
    ).join('\n');
    expect((await postEve(sensorHeaders(), big)).status).toBe(413);
    expect(
      (
        await h.app.request('/api/v1/events?from=2026-10-01T00:00:00Z&to=2026-10-19T00:00:00Z', {
          headers: authed(analyst),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await h.app.request('/api/v1/events?from=2026-10-18T00:00:00Z&to=2026-10-19T00:00:00Z', {
          headers: authed(noc),
        })
      ).status,
    ).toBe(403);
    expect((await h.app.request('/api/v1/alerts', { headers: authed(noc) })).status).toBe(200); // noc_operator holds alerts.read
  });

  it('triage follows the state machine, is audited, and reopening re-queues', async () => {
    await postEve(sensorHeaders(), alertLine());
    const [a] = (await jsonOf(await h.app.request('/api/v1/alerts', { headers: authed(analyst) })))
      .items;
    const patch = (body: unknown, token = analyst) =>
      h.app.request(`/api/v1/alerts/${a.id}`, {
        method: 'PATCH',
        headers: authed(token),
        body: JSON.stringify(body),
      });
    expect((await patch({ action: 'acknowledge' }, noc)).status).toBe(403);
    expect((await patch({ action: 'resolve' })).status).toBe(409); // note required
    expect((await patch({ action: 'suppress' })).status).toBe(400); // suppressedUntil required
    const ack = await jsonOf(await patch({ action: 'acknowledge' }));
    expect(ack.status).toBe('acknowledged');
    expect(ack.assigneeId).toBeTruthy();
    expect((await patch({ action: 'reopen', note: 'nope nope' })).status).toBe(409);
    const fp = await jsonOf(
      await patch({ action: 'false_positive', note: 'Authorized scanner from the lab segment' }),
    );
    expect(fp.status).toBe('false_positive');
    expect(
      (await jsonOf(await h.app.request('/api/v1/alerts?open=true', { headers: authed(analyst) })))
        .items,
    ).toHaveLength(0);
    // A new occurrence after disposition opens a fresh alert rather than resurrecting the closed one.
    await postEve(sensorHeaders(), alertLine({ timestamp: ts(30), flow_id: 999 }));
    const open = (
      await jsonOf(await h.app.request('/api/v1/alerts?open=true', { headers: authed(analyst) }))
    ).items;
    expect(open).toHaveLength(1);
    expect(open[0].id).not.toBe(a.id);
    const audits = (await h.handle.db.execute(
      sql`select metadata->>'action' as action from audit_events where action = 'alerts.triage' order by seq`,
    )) as unknown as Array<{ action: string }>;
    expect(audits.map((x) => x.action)).toEqual(['acknowledge', 'false_positive']);
  });
});
