import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { DetectionCoverage } from '@noc/shared';
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
let blue: string; // blue_team_engineer: detection_rules.read + change
let sec: string; // security_admin: detection_rules.deploy
let noc: string; // noc_operator: no detection_rules.read
const PW = 'coverage-password-long-enough-42';

const post = (path: string, token: string, body?: unknown) =>
  h.app.request(path, {
    method: 'POST',
    headers: authed(token),
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });
const asSensor = (cred: string) => ({
  'x-sensor-credential': cred,
  'content-type': 'application/json',
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
  ).credential as string;
  await h.handle.db.execute(sql`update sensors set enabled = true where id = ${id}`);
  return { id, cred };
}
const at = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const alertLine = (s: number, technique: string, sid = 9000001) =>
  JSON.stringify({
    timestamp: at(s),
    flow_id: 7000 + s,
    event_type: 'alert',
    src_ip: '10.20.5.9',
    src_port: 51515,
    dest_ip: '10.20.0.2',
    dest_port: 22,
    proto: 'TCP',
    alert: {
      action: 'allowed',
      gid: 1,
      signature_id: sid,
      rev: 1,
      signature: 'CUSTOM scan',
      category: 'Attempted Information Leak',
      severity: 2,
      metadata: { mitre_technique_id: [technique] },
    },
  });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table security_events, sensor_health, detection_rules, sensors cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['blue@test.local', 'blue_team_engineer'],
    ['sec@test.local', 'security_admin'],
    ['noc@test.local', 'noc_operator'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [blue, sec, noc] = (await Promise.all(
    ['blue', 'sec', 'noc'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string];
});

describe('detection coverage', () => {
  it('moves a technique from uncovered to covered only when a deployed rule is acknowledged by a running sensor', async () => {
    expect((await get('/api/v1/detection-rules/coverage', noc)).status).toBe(403);
    expect((await get('/api/v1/detection-rules/coverage?days=0', blue)).status).toBe(400);
    const empty = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage?days=7', blue)),
    );
    expect(empty.periodDays).toBe(7);
    expect(empty.summary.uncovered).toBe(empty.summary.techniques);
    expect(empty.summary.sensors).toEqual({ enabled: 0, inSync: 0, byEngine: {} });

    // A rule referencing T1046 is imported (draft) → rule_not_deployed.
    const imp = await jsonOf(
      await post('/api/v1/detection-rules/import', blue, {
        source: 'custom',
        ruleSet: 'scan',
        license: 'MIT',
        content:
          'alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:"CUSTOM scan"; sid:9000001; rev:1; classtype:attempted-recon; metadata:mitre_technique_id T1046, mitre_tactic_id TA0007;)\n',
      }),
    );
    expect(imp.imported).toBe(1);
    const find = async () =>
      (await jsonOf(await get('/api/v1/detection-rules?q=9000001', blue))).items[0] as {
        id: string;
        attackTechniques: string[];
      };
    const rule = await find();
    expect(rule.attackTechniques).toEqual(['T1046']);
    const c1 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c1.rows.find((r) => r.technique === 'T1046')).toMatchObject({
      status: 'rule_not_deployed',
      rules: { total: 1, draft: 1 },
    });

    // Deployed, but the only sensor never acknowledged the bundle → deployed_unacknowledged.
    const s = await enrol('ids-edge-1');
    expect((await post(`/api/v1/detection-rules/${rule.id}/validate`, blue)).status).toBe(200);
    expect((await get('/api/v1/detection-rules/coverage', blue)).status).toBe(200);
    expect((await post(`/api/v1/detection-rules/${rule.id}/deploy`, sec)).status).toBe(200);
    const c2 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c2.rows.find((r) => r.technique === 'T1046')).toMatchObject({
      status: 'deployed_unacknowledged',
      sensorsInSync: 0,
      rules: { deployed: 1 },
    });
    expect(c2.summary.sensors).toEqual({
      enabled: 1,
      inSync: 0,
      byEngine: { suricata: { enabled: 1, inSync: 0 } },
    });

    // The sensor fetches the bundle and heartbeats its digest → covered; observations are attributed.
    const bundle = await jsonOf(
      await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor(s.cred) }),
    );
    expect(bundle.ruleCount).toBe(1);
    expect(
      (
        await h.app.request('/api/v1/agents/heartbeat', {
          method: 'POST',
          headers: asSensor(s.cred),
          body: JSON.stringify({ state: 'healthy', rulesBundleSha256: bundle.bundleSha256 }),
        })
      ).status,
    ).toBe(204);
    const ingest = await h.app.request('/api/v1/ingest/suricata/eve', {
      method: 'POST',
      headers: { 'content-type': 'application/x-ndjson', 'x-sensor-credential': s.cred },
      // Two detections of one signature (one alert, bumped) and one of another (its own alert).
      body: [alertLine(30, 'T1046'), alertLine(20, 'T1046'), alertLine(10, 'T1595', 9000002)].join(
        '\n',
      ),
    });
    expect(ingest.status).toBe(202);
    const c3 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c3.rows.find((r) => r.technique === 'T1046')).toMatchObject({
      status: 'covered',
      sensorsInSync: 1,
      observedInPeriod: 2,
      openAlerts: 1,
    });
    expect(c3.rows.find((r) => r.technique === 'T1595')).toMatchObject({
      status: 'uncovered',
      observedInPeriod: 1,
      openAlerts: 1,
    });
    expect(c3.summary).toMatchObject({
      covered: 1,
      observedUncovered: 1,
      sensors: { enabled: 1, inSync: 1 },
    });
    expect(c3.summary.byTactic.discovery).toMatchObject({ covered: 1 });

    // Exposure: an inventoried asset listening on 3389 exposes RDP techniques; none has a rule → actionable gap.
    const obs = await jsonOf(
      await post('/api/v1/assets/observations', noc, {
        source: 'test-collector',
        method: 'arp_neighbor',
        observedAt: at(5),
        identifiers: {
          macAddresses: ['aa:bb:cc:dd:ee:09'],
          ipAddresses: ['10.20.0.9'],
          hostnames: ['jump-1'],
        },
        attributes: {},
      }),
    );
    expect(obs.assetId).toBeTruthy();
    // A listening service as the host agent would report it (the inventory path is covered elsewhere).
    await h.handle.db.execute(
      sql`insert into asset_services (asset_id, proto, port, address, source) values (${obs.assetId}::uuid, 'tcp', 3389, '10.20.0.9'::inet, 'host_agent')`,
    );
    const c4 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c4.rows.find((r) => r.technique === 'T1021.001')).toMatchObject({
      status: 'uncovered',
      exposedAssets: 1,
    });
    expect(c4.summary.exposedUncovered).toBeGreaterThanOrEqual(3); // T1021.001, T1133, T1110
  });
});
