import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { DetectionCoverage, DetectionValidation } from '@noc/shared';
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
let sec: string; // security_admin: deploy
let analyst: string; // soc_analyst: detection_rules.read only
const PW = 'validation-password-long-enough';

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

async function enrol(name: string, kind: 'suricata' | 'zeek' = 'suricata') {
  const id = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name,
        kind,
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
    ['analyst@test.local', 'soc_analyst'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [blue, sec, analyst] = (await Promise.all(
    ['blue', 'sec', 'analyst'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string];
});

describe('detection validation', () => {
  it('queues only deployed Suricata rules, derives the verdict from what the sensor reported, and proves coverage', async () => {
    const s = await enrol('ids-edge-1');
    const zk = await enrol('nsm-1', 'zeek');
    const imp = await jsonOf(
      await post('/api/v1/detection-rules/import', blue, {
        source: 'custom',
        ruleSet: 'c2',
        license: 'MIT',
        content:
          'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"CUSTOM C2"; sid:9000001; rev:1; classtype:trojan-activity; metadata:mitre_technique_id T1071;)\n',
      }),
    );
    expect(imp.imported).toBe(1);
    const rule = (await jsonOf(await get('/api/v1/detection-rules?q=9000001', blue))).items[0] as {
      id: string;
    };
    const body = { ruleId: rule.id, sensorId: s.id, sampleRef: 'c2-beacon.pcap' };

    expect((await post('/api/v1/detection-rules/validations', analyst, body)).status).toBe(403);
    expect(
      (
        await post('/api/v1/detection-rules/validations', blue, {
          ...body,
          sampleRef: '../etc/passwd',
        })
      ).status,
    ).toBe(400);
    const draft = await post('/api/v1/detection-rules/validations', blue, body);
    expect(draft.status).toBe(409);
    expect((await jsonOf(draft)).error.message).toContain('only deployed rules');
    await post(`/api/v1/detection-rules/${rule.id}/validate`, blue);
    await post(`/api/v1/detection-rules/${rule.id}/deploy`, sec);
    expect(
      (await post('/api/v1/detection-rules/validations', blue, { ...body, sensorId: zk.id }))
        .status,
    ).toBe(409);
    expect(
      (
        await post('/api/v1/detection-rules/validations', blue, {
          ...body,
          sensorId: '00000000-0000-4000-8000-000000000000',
        })
      ).status,
    ).toBe(404);

    const created = await post('/api/v1/detection-rules/validations', blue, {
      ...body,
      note: 'nightly proof',
    });
    expect(created.status).toBe(201);
    const v = DetectionValidation.parse(await jsonOf(created));
    expect(v).toMatchObject({
      status: 'queued',
      expectedSids: [9000001],
      verdict: null,
      sampleRef: 'c2-beacon.pcap',
      sensorName: 'ids-edge-1',
      ruleExternalId: '1:9000001',
    });
    expect(v.expectedBundleSha256).toMatch(/^[0-9a-f]{64}$/);

    // The sensor fetches it (dispatched); another sensor sees nothing and cannot report on it.
    const other = await enrol('ids-edge-2');
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/validations', { headers: asSensor(other.cred) }),
        )
      ).items,
    ).toEqual([]);
    const queue = await jsonOf(
      await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) }),
    );
    expect(queue.items).toHaveLength(1);
    expect(queue.items[0]).toMatchObject({
      id: v.id,
      sampleRef: 'c2-beacon.pcap',
      expectedSids: [9000001],
      expectedBundleSha256: v.expectedBundleSha256,
    });
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) }),
        )
      ).items,
    ).toEqual([]);
    expect(
      DetectionValidation.parse(
        await jsonOf(await get(`/api/v1/detection-rules/validations/${v.id}`, analyst)),
      ).status,
    ).toBe('dispatched');
    const result = {
      firedSids: [9000001, 2100498],
      rulesBundleSha256: v.expectedBundleSha256,
      engineVersion: '7.0.6',
      error: null,
      durationMs: 420,
    };
    expect(
      (
        await h.app.request(`/api/v1/agents/validations/${v.id}/result`, {
          method: 'POST',
          headers: asSensor(other.cred),
          body: JSON.stringify(result),
        })
      ).status,
    ).toBe(404);

    // Passed: expected sid fired on the expected bundle. Coverage is not yet "proven" because the
    // sensor has not acknowledged that bundle in its heartbeat.
    expect(
      (
        await h.app.request(`/api/v1/agents/validations/${v.id}/result`, {
          method: 'POST',
          headers: asSensor(s.cred),
          body: JSON.stringify(result),
        })
      ).status,
    ).toBe(204);
    const done = DetectionValidation.parse(
      await jsonOf(await get(`/api/v1/detection-rules/validations/${v.id}`, blue)),
    );
    expect(done).toMatchObject({
      status: 'completed',
      verdict: 'passed',
      firedSids: [9000001, 2100498],
      missingSids: [],
      unexpectedCount: 1,
      engineVersion: '7.0.6',
      durationMs: 420,
      error: null,
    });
    expect(
      (
        await h.app.request(`/api/v1/agents/validations/${v.id}/result`, {
          method: 'POST',
          headers: asSensor(s.cred),
          body: JSON.stringify(result),
        })
      ).status,
    ).toBe(409);
    const c0 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c0.rows.find((r) => r.technique === 'T1071')).toMatchObject({
      status: 'deployed_unacknowledged',
      rules: { deployed: 1, proven: 0 },
    });

    // Heartbeat with the bundle digest → covered and proven.
    const bundle = await jsonOf(
      await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor(s.cred) }),
    );
    expect(bundle.bundleSha256).toBe(v.expectedBundleSha256);
    await h.app.request('/api/v1/agents/heartbeat', {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ state: 'healthy', rulesBundleSha256: bundle.bundleSha256 }),
    });
    const c1 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c1.rows.find((r) => r.technique === 'T1071')).toMatchObject({
      status: 'covered',
      rules: { deployed: 1, proven: 1 },
    });
    expect(c1.summary).toMatchObject({ covered: 1, validated: 1 });

    // Failed and inconclusive outcomes are recorded as such; a wrong bundle proves nothing.
    const v2 = DetectionValidation.parse(
      await jsonOf(await post('/api/v1/detection-rules/validations', blue, body)),
    );
    await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) });
    await h.app.request(`/api/v1/agents/validations/${v2.id}/result`, {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ ...result, firedSids: [2100498] }),
    });
    expect(
      DetectionValidation.parse(
        await jsonOf(await get(`/api/v1/detection-rules/validations/${v2.id}`, blue)),
      ),
    ).toMatchObject({
      verdict: 'failed',
      missingSids: [9000001],
      error: 'expected signature(s) did not fire: 9000001',
    });
    const v3 = DetectionValidation.parse(
      await jsonOf(await post('/api/v1/detection-rules/validations', blue, body)),
    );
    await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) });
    await h.app.request(`/api/v1/agents/validations/${v3.id}/result`, {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ ...result, rulesBundleSha256: 'f'.repeat(64) }),
    });
    expect(
      DetectionValidation.parse(
        await jsonOf(await get(`/api/v1/detection-rules/validations/${v3.id}`, blue)),
      ),
    ).toMatchObject({ verdict: 'inconclusive' });
    const v4 = DetectionValidation.parse(
      await jsonOf(await post('/api/v1/detection-rules/validations', blue, body)),
    );
    await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) });
    await h.app.request(`/api/v1/agents/validations/${v4.id}/result`, {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({
        firedSids: [],
        rulesBundleSha256: bundle.bundleSha256,
        engineVersion: null,
        error: "sample 'c2-beacon.pcap' is not available on this sensor",
        durationMs: 1,
      }),
    });
    expect(
      DetectionValidation.parse(
        await jsonOf(await get(`/api/v1/detection-rules/validations/${v4.id}`, blue)),
      ),
    ).toMatchObject({
      status: 'failed',
      verdict: 'inconclusive',
      error: "sample 'c2-beacon.pcap' is not available on this sensor",
    });

    // A queued validation nobody answers expires; the earlier pass still proves the rule.
    const v5 = DetectionValidation.parse(
      await jsonOf(await post('/api/v1/detection-rules/validations', blue, body)),
    );
    await h.handle.db.execute(
      sql`update detection_validations set expires_at = now() - interval '1 minute' where id = ${v5.id}`,
    );
    const list = (await jsonOf(await get('/api/v1/detection-rules/validations?limit=10', analyst)))
      .items as DetectionValidation[];
    expect(list.map((x) => [x.id, x.status, x.verdict])).toEqual([
      [v5.id, 'expired', null],
      [v4.id, 'failed', 'inconclusive'],
      [v3.id, 'completed', 'inconclusive'],
      [v2.id, 'completed', 'failed'],
      [v.id, 'completed', 'passed'],
    ]);
    expect(
      (
        await jsonOf(
          await get(
            `/api/v1/detection-rules/validations?ruleId=${rule.id}&sensorId=${other.id}`,
            analyst,
          ),
        )
      ).items,
    ).toEqual([]);
    const c2 = DetectionCoverage.parse(
      await jsonOf(await get('/api/v1/detection-rules/coverage', blue)),
    );
    expect(c2.rows.find((r) => r.technique === 'T1071')?.rules.proven).toBe(1);

    const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
    const acts = (audit.items as Array<{ action: string; outcome: string }>).filter((a) =>
      a.action.startsWith('detection_rules.validat'),
    );
    expect(
      acts.filter((a) => a.action === 'detection_rules.validate' && a.outcome === 'denied').length,
    ).toBeGreaterThanOrEqual(2);
    expect(acts.filter((a) => a.action === 'detection_rules.validation_result')).toHaveLength(4);
  });
});
