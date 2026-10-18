import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { RuleBundle } from '@noc/shared';
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
let blue: string; // blue_team_engineer: detection_rules.change (no deploy)
let sec: string; // security_admin: detection_rules.deploy (no change)
let noc: string; // noc_operator: network.manage for sites
const PW = 'rules-deploy-password-long-enough';

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

async function enrol(name: string, kind: 'suricata' | 'zeek', site: string | null) {
  const id = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name,
        kind,
        site,
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
const bundle = (cred: string, etag?: string) =>
  h.app.request('/api/v1/agents/rules-bundle', {
    headers: { ...asSensor(cred), ...(etag ? { 'if-none-match': etag } : {}) },
  });
const heartbeat = (cred: string, sha: string | null) =>
  h.app.request('/api/v1/agents/heartbeat', {
    method: 'POST',
    headers: asSensor(cred),
    body: JSON.stringify({ state: 'healthy', rulesBundleSha256: sha }),
  });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(sql`truncate table sensor_health, detection_rules, sensors cascade`);
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

describe('rule deployment bundles', () => {
  it('deploys under separation of duties, targets by site, serves per-sensor bundles and tracks acknowledgement', async () => {
    for (const k of ['dc1', 'branch'])
      expect((await post('/api/v1/sites', noc, { key: k, name: k })).status).toBe(201);
    const dc = await enrol('ids-dc1', 'suricata', 'dc1');
    const br = await enrol('ids-branch', 'suricata', 'branch');
    const zk = await enrol('nsm-dc1', 'zeek', 'dc1');
    const imp = await jsonOf(
      await post('/api/v1/detection-rules/import', blue, {
        source: 'custom',
        ruleSet: 'c2',
        license: 'MIT',
        content:
          'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"CUSTOM C2 beacon"; sid:9000001; rev:1; classtype:trojan-activity;)\n' +
          'alert tcp $HOME_NET any -> $EXTERNAL_NET 5555 (msg:"CUSTOM C2 beacon 2"; sid:9000002; rev:1; classtype:trojan-activity;)\n',
      }),
    );
    expect(imp.imported).toBe(2);
    const find = async (sid: string) =>
      (await jsonOf(await get(`/api/v1/detection-rules?q=${sid}`, blue))).items[0] as {
        id: string;
        lifecycle: string;
        sites: string[];
      };
    const r1 = await find('9000001');
    const r2 = await find('9000002');

    // Nothing deployed yet: bundles are empty but well-formed, and identical for the two Suricata sensors.
    const empty = RuleBundle.parse(await jsonOf(await bundle(dc.cred)));
    expect(empty).toMatchObject({ engine: 'suricata', site: 'dc1', ruleCount: 0, rules: [] });
    expect((await jsonOf(await bundle(br.cred))).bundleSha256).toBe(empty.bundleSha256);
    expect((await jsonOf(await bundle(zk.cred))).engine).toBe('zeek');

    // Deploy: draft refused (409), engineer refused (403, SoD), admin deploys validated rules.
    expect((await post(`/api/v1/detection-rules/${r1.id}/deploy`, sec)).status).toBe(409);
    await post(`/api/v1/detection-rules/${r1.id}/validate`, blue);
    await post(`/api/v1/detection-rules/${r2.id}/validate`, blue);
    expect((await post(`/api/v1/detection-rules/${r1.id}/deploy`, blue)).status).toBe(403);
    expect(
      (await jsonOf(await post(`/api/v1/detection-rules/${r1.id}/deploy`, sec))).lifecycle,
    ).toBe('deployed');
    expect(
      (await jsonOf(await post(`/api/v1/detection-rules/${r2.id}/deploy`, sec))).lifecycle,
    ).toBe('deployed');
    // Targets: unknown site refused; r2 only for dc1.
    expect(
      (
        await h.app.request(`/api/v1/detection-rules/${r2.id}/targets`, {
          method: 'PUT',
          headers: authed(blue),
          body: JSON.stringify({ sites: ['nowhere'] }),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/detection-rules/${r2.id}/targets`, {
            method: 'PUT',
            headers: authed(blue),
            body: JSON.stringify({ sites: ['dc1'] }),
          }),
        )
      ).sites,
    ).toEqual(['dc1']);

    // Bundles now differ by site; the Zeek sensor gets no Suricata rules; ETag round-trips as 304.
    const dcBundle = RuleBundle.parse(await jsonOf(await bundle(dc.cred)));
    expect(dcBundle.rules.map((r) => r.externalId)).toEqual(['1:9000001', '1:9000002']);
    expect(dcBundle.rules[0]!.content).toMatch(/sid:9000001/);
    const brBundle = RuleBundle.parse(await jsonOf(await bundle(br.cred)));
    expect(brBundle.rules.map((r) => r.externalId)).toEqual(['1:9000001']);
    expect(brBundle.bundleSha256).not.toBe(dcBundle.bundleSha256);
    expect((await jsonOf(await bundle(zk.cred))).ruleCount).toBe(0);
    const notModified = await bundle(dc.cred, `"${dcBundle.bundleSha256}"`);
    expect(notModified.status).toBe(304);
    expect(
      (await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor('bogus') })).status,
    ).toBe(401);

    // Acknowledgement through the heartbeat drives the deployment view.
    const state = async () =>
      (await jsonOf(await get('/api/v1/detection-rules/deployment', blue))).items as Array<{
        sensorName: string;
        inSync: boolean;
        expectedRuleCount: number;
        appliedBundleSha256: string | null;
        engine: string | null;
      }>;
    expect((await state()).every((s) => !s.inSync)).toBe(true);
    expect((await heartbeat(dc.cred, dcBundle.bundleSha256)).status).toBe(204);
    expect((await heartbeat(br.cred, dcBundle.bundleSha256)).status).toBe(204); // wrong bundle for branch
    const s1 = await state();
    expect(s1.find((s) => s.sensorName === 'ids-dc1')).toMatchObject({
      inSync: true,
      expectedRuleCount: 2,
      engine: 'suricata',
    });
    expect(s1.find((s) => s.sensorName === 'ids-branch')).toMatchObject({
      inSync: false,
      expectedRuleCount: 1,
    });
    expect(s1.find((s) => s.sensorName === 'nsm-dc1')).toMatchObject({
      inSync: false,
      expectedRuleCount: 0,
      engine: 'zeek',
    });
    // Disabling a rule changes the expected bundle: dc1 is out of sync until it re-fetches and acks.
    await post(`/api/v1/detection-rules/${r2.id}/lifecycle`, blue, { lifecycle: 'disabled' });
    expect((await state()).find((s) => s.sensorName === 'ids-dc1')!.inSync).toBe(false);
    const refreshed = RuleBundle.parse(await jsonOf(await bundle(dc.cred)));
    expect(refreshed.ruleCount).toBe(1);
    await heartbeat(dc.cred, refreshed.bundleSha256);
    expect((await state()).find((s) => s.sensorName === 'ids-dc1')!.inSync).toBe(true);
    // The sensor record exposes what it acknowledged.
    expect(
      (await jsonOf(await get(`/api/v1/sensors/${dc.id}/status`, admin.token))).sensor
        .rulesBundleSha256,
    ).toBe(refreshed.bundleSha256);

    const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
    const acts = audit.items.map(
      (e: { action: string; outcome: string }) => `${e.action}:${e.outcome}`,
    );
    expect(acts.filter((a: string) => a === 'detection_rules.deploy:success')).toHaveLength(2);
    expect(acts).toContain('detection_rules.targets:success');
  });
});
