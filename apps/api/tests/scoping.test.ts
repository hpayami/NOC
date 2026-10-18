import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { SessionUser } from '@noc/shared';
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
let noc: string; // noc_operator: assets.manage, network.manage, sensors.read
let analystId: string;
let analyst: string; // soc_analyst
let blueId: string;
let blue: string; // blue_team_engineer: events.ingest for alert seeding, ml.read/manage
const PW = 'scoping-password-that-is-long-enough';

const post = (path: string, token: string, body: unknown) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });
const segment = (name: string, site: string, cidr: string) =>
  post('/api/v1/network/segments', noc, {
    name,
    site,
    cidr,
    vlanId: null,
    activeDiscoveryAllowed: false,
    description: null,
  });
const observe = (ip: string, mac: string, host: string) =>
  post('/api/v1/assets/observations', noc, {
    source: 'test',
    method: 'passive_observation',
    observedAt: new Date().toISOString(),
    identifiers: { macAddresses: [mac], ipAddresses: [ip], hostnames: [host] },
    attributes: {},
  });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, network_segments, security_events, sensors cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'noc@test.local',
    password: PW,
    roles: ['noc_operator'],
  });
  const a = await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  analystId = a.body.id;
  const b = await createUser(h, admin.token, {
    email: 'blue@test.local',
    password: PW,
    roles: ['blue_team_engineer'],
  });
  blueId = b.body.id;
  noc = (await login(h, 'noc@test.local', PW)).body.accessToken;
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken;
});

describe('site scoping', () => {
  it('restricts a user to granted sites across assets, segments, sensors, alerts and events; unrestricted users see all', async () => {
    // Sites and one segment + asset + sensor per site; a sensor with no site; an asset with no segment.
    for (const s of [
      { key: 'dc1', name: 'Datacentre 1' },
      { key: 'branch', name: 'Branch office' },
    ])
      expect((await post('/api/v1/sites', noc, s)).status).toBe(201);
    expect((await post('/api/v1/sites', noc, { key: 'dc1', name: 'dup' })).status).toBe(409);
    expect((await post('/api/v1/sites', analyst, { key: 'x', name: 'x' })).status).toBe(403);
    await segment('dc1-servers', 'dc1', '10.1.0.0/24');
    await segment('branch-users', 'branch', '10.2.0.0/24');
    const dcAsset = (await jsonOf(await observe('10.1.0.10', 'aa:aa:aa:aa:aa:01', 'srv-01')))
      .assetId as string;
    const brAsset = (await jsonOf(await observe('10.2.0.10', 'aa:aa:aa:aa:aa:02', 'pc-01')))
      .assetId as string;
    const orphan = (await jsonOf(await observe('192.168.77.5', 'aa:aa:aa:aa:aa:03', 'orphan')))
      .assetId as string;
    for (const [name, site] of [
      ['ids-dc1', 'dc1'],
      ['ids-branch', 'branch'],
      ['ids-nosite', null],
    ] as const)
      expect(
        (
          await post('/api/v1/sensors', admin.token, {
            name,
            kind: 'suricata',
            site,
            monitoredSegmentIds: [],
            engineVersion: null,
          })
        ).status,
      ).toBe(201);
    const sensorsAll = await jsonOf(await get('/api/v1/sensors', admin.token));
    const dcSensor = sensorsAll.find(
      (s: { sensor: { name: string } }) => s.sensor.name === 'ids-dc1',
    ).sensor.id;
    // Alerts: one hitting the DC asset, one hitting the branch asset, one with no asset.
    const eve = (sid: number, dst: string) =>
      JSON.stringify({
        timestamp: '2026-10-18T10:00:00.000000+0000',
        flow_id: sid,
        event_type: 'alert',
        src_ip: '203.0.113.9',
        src_port: 4444,
        dest_ip: dst,
        dest_port: 445,
        proto: 'TCP',
        alert: {
          action: 'allowed',
          gid: 1,
          signature_id: sid,
          rev: 1,
          signature: `ET TEST ${sid}`,
          category: 'Attempted Administrator Privilege Gain',
          severity: 1,
        },
      });
    const ing = await h.app.request(`/api/v1/ingest/suricata/eve?sensorId=${dcSensor}`, {
      method: 'POST',
      headers: { ...authed(blue), 'content-type': 'application/x-ndjson' },
      body: [eve(1, '10.1.0.10'), eve(2, '10.2.0.10'), eve(3, '198.51.100.7')].join('\n'),
    });
    expect(ing.status).toBe(202);

    // Unrestricted analyst sees everything.
    expect((await jsonOf(await get('/api/v1/assets?limit=50', analyst))).items).toHaveLength(3);
    expect((await jsonOf(await get('/api/v1/alerts?open=true', analyst))).items).toHaveLength(3);
    expect((await jsonOf(await get('/api/v1/sites', analyst))).restricted).toBe(false);

    // Restrict the analyst to dc1: tokens are invalidated immediately.
    expect(
      (
        await h.app.request(`/api/v1/users/${analystId}/sites`, {
          method: 'PUT',
          headers: authed(admin.token),
          body: JSON.stringify({ allSites: false, sites: ['nowhere'] }),
        })
      ).status,
    ).toBe(400);
    const upd = await h.app.request(`/api/v1/users/${analystId}/sites`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ allSites: false, sites: ['dc1'] }),
    });
    expect(upd.status).toBe(200);
    expect(await jsonOf(upd)).toMatchObject({ allSites: false, sites: ['dc1'] });
    expect((await get('/api/v1/assets', analyst)).status).toBe(401);
    const rl = await login(h, 'analyst@test.local', PW);
    analyst = rl.body.accessToken;
    expect(SessionUser.parse(rl.body.user).sites).toEqual(['dc1']);

    const assets = await jsonOf(await get('/api/v1/assets?limit=50', analyst));
    expect(assets.items.map((a: { id: string }) => a.id)).toEqual([dcAsset]);
    expect((await get(`/api/v1/assets/${dcAsset}`, analyst)).status).toBe(200);
    expect((await get(`/api/v1/assets/${brAsset}`, analyst)).status).toBe(404); // not 403: existence is not leaked
    expect((await get(`/api/v1/assets/${orphan}`, analyst)).status).toBe(404); // unattributable rows are hidden
    expect(
      (await jsonOf(await get('/api/v1/network/segments', analyst))).map(
        (s: { name: string }) => s.name,
      ),
    ).toEqual(['dc1-servers']);
    expect(
      (await jsonOf(await get('/api/v1/sensors', analyst))).map(
        (s: { sensor: { name: string } }) => s.sensor.name,
      ),
    ).toEqual(['ids-dc1']);
    const alerts = await jsonOf(await get('/api/v1/alerts?open=true', analyst));
    expect(alerts.items).toHaveLength(1);
    expect(alerts.items[0].assetId).toBe(dcAsset);
    const hidden = (await jsonOf(await get('/api/v1/alerts?open=true', noc))).items.find(
      (a: { assetId: string | null }) => a.assetId === brAsset,
    );
    expect((await get(`/api/v1/alerts/${hidden.id}`, analyst)).status).toBe(404);
    const from = encodeURIComponent('2026-10-18T00:00:00Z');
    const to = encodeURIComponent('2026-10-19T00:00:00Z');
    const events = await jsonOf(await get(`/api/v1/events?from=${from}&to=${to}`, analyst));
    expect(events.items).toHaveLength(1);
    expect(events.items[0].dstAssetId).toBe(dcAsset);
    expect(
      (await jsonOf(await get('/api/v1/sites', analyst))).items.map((s: { key: string }) => s.key),
    ).toEqual(['dc1']);

    // Restricted with no grants = sees nothing (fail closed), never everything.
    await h.app.request(`/api/v1/users/${analystId}/sites`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ allSites: false, sites: [] }),
    });
    analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
    expect((await jsonOf(await get('/api/v1/assets?limit=50', analyst))).items).toHaveLength(0);
    expect((await jsonOf(await get('/api/v1/alerts?open=true', analyst))).items).toHaveLength(0);
    // Back to unrestricted.
    await h.app.request(`/api/v1/users/${analystId}/sites`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ allSites: true }),
    });
    analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
    expect((await jsonOf(await get('/api/v1/assets?limit=50', analyst))).items).toHaveLength(3);
    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    expect(
      audit.items.filter((e: { action: string }) => e.action === 'users.set_sites'),
    ).toHaveLength(3);
    expect(audit.items.some((e: { action: string }) => e.action === 'sites.create')).toBe(true);
  });

  it('scopes incidents, response actions, findings and ML results, and refuses out-of-scope writes', async () => {
    for (const k of ['dc1', 'branch'])
      expect((await post('/api/v1/sites', noc, { key: k, name: k })).status).toBe(201);
    await segment('dc1-servers', 'dc1', '10.1.0.0/24');
    await segment('branch-users', 'branch', '10.2.0.0/24');
    const dcAsset = (await jsonOf(await observe('10.1.0.10', 'aa:aa:aa:aa:aa:01', 'srv-01')))
      .assetId as string;
    const brAsset = (await jsonOf(await observe('10.2.0.10', 'aa:aa:aa:aa:aa:02', 'pc-01')))
      .assetId as string;
    const sensor = await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name: 'ids-dc1',
        kind: 'suricata',
        site: 'dc1',
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    );
    const eve = (sid: number, dst: string) =>
      JSON.stringify({
        timestamp: '2026-10-18T10:00:00.000000+0000',
        flow_id: sid,
        event_type: 'alert',
        src_ip: '203.0.113.9',
        src_port: 4444,
        dest_ip: dst,
        dest_port: 445,
        proto: 'TCP',
        alert: {
          action: 'allowed',
          gid: 1,
          signature_id: sid,
          rev: 1,
          signature: `ET TEST ${sid}`,
          category: 'Attempted Administrator Privilege Gain',
          severity: 1,
        },
      });
    expect(
      (
        await h.app.request(`/api/v1/ingest/suricata/eve?sensorId=${sensor.id}`, {
          method: 'POST',
          headers: { ...authed(blue), 'content-type': 'application/x-ndjson' },
          body: [eve(1, '10.1.0.10'), eve(2, '10.2.0.10')].join('\n'),
        })
      ).status,
    ).toBe(202);
    const allAlerts = (await jsonOf(await get('/api/v1/alerts?open=true', noc))).items as Array<{
      id: string;
      assetId: string;
    }>;
    const dcAlert = allAlerts.find((a) => a.assetId === dcAsset)!.id;
    const brAlert = allAlerts.find((a) => a.assetId === brAsset)!.id;

    // Unrestricted: site inferred from the first attached alert, explicit, or global (null).
    const inc = (body: Record<string, unknown>, token = analyst) =>
      post('/api/v1/incidents', token, { title: 'Incident', severity: 'high', ...body });
    const dcInc = await jsonOf(await inc({ alertIds: [dcAlert] }));
    expect(dcInc.site).toBe('dc1');
    const brInc = await jsonOf(await inc({ site: 'branch' }));
    expect(brInc.site).toBe('branch');
    const globalInc = await jsonOf(await inc({}));
    expect(globalInc.site).toBeNull();
    expect((await inc({ site: 'nope' })).status).toBe(400);
    const proposal = (incidentId: string) => ({
      kind: 'escalate',
      incidentId,
      targetType: 'incident',
      targetRef: incidentId,
      justification: 'Escalate for scoping test coverage',
      rollbackPlan: 'Lower the severity back to the previous value',
    });
    const globalAction = await jsonOf(
      await post('/api/v1/response-actions', analyst, proposal(globalInc.id)),
    );
    expect(globalAction.id).toBeTruthy();
    const finding = (assetId: string, title: string) =>
      h.handle.db.execute(
        sql`insert into vulnerability_findings (asset_id, title, severity, description) values (${assetId}::uuid, ${title}, 'high', 'test')`,
      );
    await finding(dcAsset, 'SMB exposed');
    await finding(brAsset, 'RDP exposed');
    const mlRow = (assetId: string) =>
      h.handle.db.execute(
        sql`insert into ml_inference_results (model_name, model_version, feature_set_version, subject_type, subject_id, score, window_start, window_end) values ('baseline', '1', '1', 'asset', ${assetId}, 0.9, now() - interval '1 day', now())`,
      );
    await mlRow(dcAsset);
    await mlRow(brAsset);
    expect((await jsonOf(await get('/api/v1/findings', analyst))).items).toHaveLength(2);
    expect((await jsonOf(await get('/api/v1/ml/results', blue))).items).toHaveLength(2);

    // Restrict analyst and blue to dc1.
    for (const id of [analystId, blueId])
      expect(
        (
          await h.app.request(`/api/v1/users/${id}/sites`, {
            method: 'PUT',
            headers: authed(admin.token),
            body: JSON.stringify({ allSites: false, sites: ['dc1'] }),
          })
        ).status,
      ).toBe(200);
    analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
    blue = (await login(h, 'blue@test.local', PW)).body.accessToken;

    // Reads: only dc1 incidents; branch and global ones do not exist from this account's view.
    const list = await jsonOf(await get('/api/v1/incidents?limit=50', analyst));
    expect(list.items.map((i: { id: string }) => i.id)).toEqual([dcInc.id]);
    expect((await jsonOf(await get('/api/v1/incidents/stats', analyst))).total).toBe(1);
    expect((await get(`/api/v1/incidents/${dcInc.id}`, analyst)).status).toBe(200);
    expect((await get(`/api/v1/incidents/${brInc.id}`, analyst)).status).toBe(404);
    expect((await get(`/api/v1/incidents/${globalInc.id}`, analyst)).status).toBe(404);
    expect(
      (
        await post(`/api/v1/incidents/${brInc.id}/transition`, analyst, {
          to: 'triage',
        })
      ).status,
    ).toBe(404);
    // Writes: site outside the grants is refused and audited; no site at all is refused; an
    // out-of-scope alert cannot be attached (reported as absent).
    expect((await inc({ site: 'branch' })).status).toBe(403);
    expect((await inc({})).status).toBe(400);
    expect((await inc({ alertIds: [brAlert] })).status).toBe(404);
    const mine = await jsonOf(await inc({ site: 'dc1' }));
    expect(mine.site).toBe('dc1');
    expect(
      (await post(`/api/v1/incidents/${mine.id}/alerts`, analyst, { alertIds: [brAlert] })).status,
    ).toBe(404);
    // Response actions follow their incident.
    expect((await post('/api/v1/response-actions', analyst, proposal(brInc.id))).status).toBe(404);
    const dcAction = await jsonOf(
      await post('/api/v1/response-actions', analyst, proposal(dcInc.id)),
    );
    expect(dcAction.incidentId).toBe(dcInc.id);
    const actions = await jsonOf(await get('/api/v1/response-actions?limit=50', analyst));
    expect(actions.items.map((a: { id: string }) => a.id)).toEqual([dcAction.id]);
    expect((await get(`/api/v1/response-actions/${globalAction.id}`, analyst)).status).toBe(404);
    // Findings and ML results follow their asset.
    const findings = await jsonOf(await get('/api/v1/findings', analyst));
    expect(findings.items.map((f: { assetId: string }) => f.assetId)).toEqual([dcAsset]);
    const results = await jsonOf(await get('/api/v1/ml/results', blue));
    expect(results.items.map((r: { subjectId: string }) => r.subjectId)).toEqual([dcAsset]);
    expect(
      (await post('/api/v1/ml/score', blue, { subjectType: 'asset', subjectId: brAsset })).status,
    ).toBe(404);

    const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
    expect(
      audit.items.some(
        (e: { action: string; outcome: string; metadata: { reason?: string } }) =>
          e.action === 'incidents.create' &&
          e.outcome === 'denied' &&
          e.metadata.reason === 'site_not_granted',
      ),
    ).toBe(true);
  });
});
