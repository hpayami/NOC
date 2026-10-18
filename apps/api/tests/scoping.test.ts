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
let blue: string; // events.ingest for alert seeding
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
  await createUser(h, admin.token, {
    email: 'blue@test.local',
    password: PW,
    roles: ['blue_team_engineer'],
  });
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
});
