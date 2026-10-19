import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import {
  DetectionCoverage,
  DetectionValidation,
  PlatformConditions,
  ValidationSchedule,
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
import { SCHEDULE_LOCK_KEY, ValidationService } from '../src/rules/validation';
import { AuditService } from '../src/audit/service';

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

async function enrol(
  name: string,
  kind: 'suricata' | 'zeek' = 'suricata',
  site: string | null = null,
) {
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

/** Import a custom C2 rule, then walk it through draft → validated → deployed. */
async function importDeployRule() {
  await post('/api/v1/detection-rules/import', blue, {
    source: 'custom',
    ruleSet: 'c2',
    license: 'MIT',
    content:
      'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"CUSTOM C2"; sid:9000001; rev:1; classtype:trojan-activity;)\n',
  });
  const rule = (await jsonOf(await get('/api/v1/detection-rules?q=9000001', blue))).items[0] as {
    id: string;
  };
  await post(`/api/v1/detection-rules/${rule.id}/validate`, blue);
  await post(`/api/v1/detection-rules/${rule.id}/deploy`, sec);
  return rule.id;
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

  it('re-proves rules on a schedule, backs off after failures, and surfaces failures as a platform condition', async () => {
    const s = await enrol('ids-edge-1');
    await post('/api/v1/detection-rules/import', blue, {
      source: 'custom',
      ruleSet: 'c2',
      license: 'MIT',
      content:
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"CUSTOM C2"; sid:9000001; rev:1; classtype:trojan-activity;)\n',
    });
    const rule = (await jsonOf(await get('/api/v1/detection-rules?q=9000001', blue))).items[0] as {
      id: string;
    };
    await post(`/api/v1/detection-rules/${rule.id}/validate`, blue);
    await post(`/api/v1/detection-rules/${rule.id}/deploy`, sec);
    const svc = new ValidationService(h.handle.db, new AuditService(h.handle.db));
    const body = { ruleId: rule.id, sensorId: s.id, sampleRef: 'c2-beacon.pcap', intervalDays: 7 };

    expect((await post('/api/v1/detection-rules/validation-schedules', analyst, body)).status).toBe(
      403,
    );
    const created = await post('/api/v1/detection-rules/validation-schedules', blue, body);
    expect(created.status).toBe(201);
    const sched = ValidationSchedule.parse(await jsonOf(created));
    expect(sched).toMatchObject({
      intervalDays: 7,
      enabled: true,
      lastError: null,
      lastVerdict: null,
      sensorName: 'ids-edge-1',
    });
    expect(sched.lastQueuedAt).not.toBeNull();
    // Creating queued the first validation; the scheduler must not queue a second while it is pending.
    let list = (await jsonOf(await get('/api/v1/detection-rules/validations', blue)))
      .items as DetectionValidation[];
    expect(list).toHaveLength(1);
    expect(await svc.runSchedules()).toEqual({ queued: 0, skipped: 1, errors: 0 });

    // Sensor passes it with the right bundle → not due again until the interval elapses.
    const bundle = await jsonOf(
      await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor(s.cred) }),
    );
    const take = async () =>
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) }),
        )
      ).items as Array<{ id: string }>;
    const report = (id: string, fired: number[]) =>
      h.app.request(`/api/v1/agents/validations/${id}/result`, {
        method: 'POST',
        headers: asSensor(s.cred),
        body: JSON.stringify({
          firedSids: fired,
          rulesBundleSha256: bundle.bundleSha256,
          engineVersion: '7.0.6',
          error: null,
          durationMs: 5,
        }),
      });
    const [q1] = await take();
    await report(q1!.id, [9000001]);
    expect(await svc.runSchedules()).toEqual({ queued: 0, skipped: 1, errors: 0 });
    expect(await svc.runSchedules(new Date(Date.now() + 8 * 86_400_000))).toEqual({
      queued: 1,
      skipped: 0,
      errors: 0,
    });
    list = (await jsonOf(await get('/api/v1/detection-rules/validations', blue)))
      .items as DetectionValidation[];
    expect(list).toHaveLength(2);
    expect(list[0]).toMatchObject({ status: 'queued', sampleRef: 'c2-beacon.pcap' });

    // A failed outcome is a condition and is not re-queued every tick: the interval applies to attempts too.
    const [q2] = await take();
    await report(q2!.id, [2100498]);
    const schedules = (
      await jsonOf(await get('/api/v1/detection-rules/validation-schedules', analyst))
    ).items as ValidationSchedule[];
    expect(schedules[0]).toMatchObject({ id: sched.id, lastVerdict: 'failed' });
    expect(await svc.runSchedules(new Date(Date.now() + 1 * 86_400_000))).toEqual({
      queued: 0,
      skipped: 1,
      errors: 0,
    });
    expect(await svc.runSchedules(new Date(Date.now() + 8 * 86_400_000))).toEqual({
      queued: 1,
      skipped: 0,
      errors: 0,
    });
    const cond = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', blue)),
    );
    const dv = cond.conditions.find((c) => c.id === 'detection_validation_failures');
    expect(dv).toMatchObject({ severity: 'warning', count: 1, link: '/blue-team' });
    expect(dv!.detail).toContain('1:9000001 CUSTOM C2');

    // Admission refusals land on the schedule and in the condition; disabling the schedule silences it.
    const [q3] = await take();
    await report(q3!.id, [9000001]);
    await h.handle.db.execute(sql`update sensors set enabled = false where id = ${s.id}`);
    expect(await svc.runSchedules(new Date(Date.now() + 40 * 86_400_000))).toEqual({
      queued: 0,
      skipped: 0,
      errors: 1,
    });
    const stuck = (await jsonOf(await get('/api/v1/detection-rules/validation-schedules', blue)))
      .items as ValidationSchedule[];
    expect(stuck[0]!.lastError).toContain('Sensor is disabled');
    const cond2 = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', blue)),
    );
    expect(
      cond2.conditions.find((c) => c.id === 'detection_validation_failures')?.detail,
    ).toContain('ids-edge-1: Sensor is disabled');
    expect(
      (
        await h.app.request(`/api/v1/detection-rules/validation-schedules/${sched.id}`, {
          method: 'PATCH',
          headers: authed(analyst),
          body: JSON.stringify({ enabled: false }),
        })
      ).status,
    ).toBe(403);
    const off = await h.app.request(`/api/v1/detection-rules/validation-schedules/${sched.id}`, {
      method: 'PATCH',
      headers: authed(blue),
      body: JSON.stringify({ enabled: false, intervalDays: 3 }),
    });
    expect(off.status).toBe(200);
    expect(ValidationSchedule.parse(await jsonOf(off))).toMatchObject({
      enabled: false,
      intervalDays: 3,
    });
    expect(await svc.runSchedules(new Date(Date.now() + 40 * 86_400_000))).toEqual({
      queued: 0,
      skipped: 0,
      errors: 0,
    });
    const cond3 = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', blue)),
    );
    expect(cond3.conditions.find((c) => c.id === 'detection_validation_failures')).toBeUndefined();
    expect(
      (
        await h.app.request(
          '/api/v1/detection-rules/validation-schedules/00000000-0000-4000-8000-000000000000',
          { method: 'PATCH', headers: authed(blue), body: JSON.stringify({ enabled: true }) },
        )
      ).status,
    ).toBe(404);

    const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
    const acts = (audit.items as Array<{ action: string; actorLabel?: string }>).filter(
      (a) => a.action === 'detection_rules.validate',
    );
    expect(acts.some((a) => a.actorLabel === 'system:validation-scheduler')).toBe(true);
  });

  it('pages schedules with a keyset cursor, and an unknown cursor returns the first page instead of erroring', async () => {
    const ruleId = await importDeployRule();
    const ids: string[] = [];
    for (const name of ['ids-page-1', 'ids-page-2', 'ids-page-3']) {
      const s = await enrol(name);
      const created = await post('/api/v1/detection-rules/validation-schedules', blue, {
        ruleId,
        sensorId: s.id,
        sampleRef: 'c2-beacon.pcap',
        intervalDays: 7,
      });
      expect(created.status).toBe(201);
      ids.push(ValidationSchedule.parse(await jsonOf(created)).id);
    }

    const p1 = await jsonOf(
      await get('/api/v1/detection-rules/validation-schedules?limit=2', blue),
    );
    expect(p1.items).toHaveLength(2);
    expect(p1.nextCursor).toBe(p1.items[1].id);
    const p2raw = await get(
      `/api/v1/detection-rules/validation-schedules?limit=2&cursor=${p1.nextCursor}`,
      blue,
    );
    expect(p2raw.status).toBe(200);
    const p2 = await jsonOf(p2raw);
    expect(p2.items).toHaveLength(1);
    expect(p2.nextCursor).toBeNull();
    // Newest-first, and the pages together are exactly what was created.
    expect(p1.items[0].id).toBe(ids[2]);
    expect([...p1.items, ...p2.items].map((x: { id: string }) => x.id)).toEqual(
      expect.arrayContaining(ids),
    );

    // A stale or fabricated cursor is a link, not an existence oracle: back to the first page.
    const stale = await jsonOf(
      await get(
        '/api/v1/detection-rules/validation-schedules?limit=2&cursor=00000000-0000-4000-8000-000000000000',
        blue,
      ),
    );
    expect(stale.items.map((x: { id: string }) => x.id)).toEqual(
      p1.items.map((x: { id: string }) => x.id),
    );
    // The page cannot be widened past the documented cap.
    const wide = await get('/api/v1/detection-rules/validation-schedules?limit=5000', blue);
    expect(wide.status).toBe(400);
  });

  it('treats a sensor or schedule outside the caller site scope as missing rather than forbidden', async () => {
    for (const [key, name] of [
      ['dc1', 'DC1'],
      ['dc2', 'DC2'],
    ] as const)
      expect((await post('/api/v1/sites', admin.token, { key, name })).status).toBe(201);
    const ruleId = await importDeployRule();
    const held = await enrol('ids-dc1', 'suricata', 'dc1');
    const outside = await enrol('ids-dc2', 'suricata', 'dc2');

    // The unrestricted engineer can schedule on the dc2 sensor; that row then exists.
    const base = await post('/api/v1/detection-rules/validation-schedules', blue, {
      ruleId,
      sensorId: outside.id,
      sampleRef: 'c2-beacon.pcap',
      intervalDays: 7,
    });
    expect(base.status).toBe(201);
    const hiddenId = ValidationSchedule.parse(await jsonOf(base)).id;

    // A colleague holding only dc1 must not be able to see, create or touch it.
    const u = await createUser(h, admin.token, {
      email: 'scoped@test.local',
      password: PW,
      roles: ['blue_team_engineer'],
    });
    expect(
      (
        await h.app.request(`/api/v1/users/${u.body.id}/sites`, {
          method: 'PUT',
          headers: authed(admin.token),
          body: JSON.stringify({ allSites: false, sites: ['dc1'] }),
        })
      ).status,
    ).toBe(200);
    const scoped = (await login(h, 'scoped@test.local', PW)).body.accessToken as string;

    expect(
      (
        await post('/api/v1/detection-rules/validations', scoped, {
          ruleId,
          sensorId: outside.id,
          sampleRef: 'c2-beacon.pcap',
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await post('/api/v1/detection-rules/validation-schedules', scoped, {
          ruleId,
          sensorId: outside.id,
          sampleRef: 'c2-beacon.pcap',
          intervalDays: 7,
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await h.app.request(`/api/v1/detection-rules/validation-schedules/${hiddenId}`, {
          method: 'PATCH',
          headers: authed(scoped),
          body: JSON.stringify({ enabled: false }),
        })
      ).status,
    ).toBe(404);
    const list = (await jsonOf(
      await get('/api/v1/detection-rules/validation-schedules', scoped),
    )) as { items: ValidationSchedule[] };
    expect(list.items).toEqual([]);

    // The sensor they do hold is scheduleable, so the 404s above were scope, not a broken grant.
    const own = await post('/api/v1/detection-rules/validation-schedules', scoped, {
      ruleId,
      sensorId: held.id,
      sampleRef: 'c2-beacon.pcap',
      intervalDays: 7,
    });
    expect(own.status).toBe(201);
  });

  it('stamps reported-at when a validation expires, so an unanswered sensor waits a full interval', async () => {
    const s = await enrol('ids-edge-1');
    const ruleId = await importDeployRule();
    const created = await post('/api/v1/detection-rules/validation-schedules', blue, {
      ruleId,
      sensorId: s.id,
      sampleRef: 'c2-beacon.pcap',
      intervalDays: 7,
    });
    expect(created.status).toBe(201);
    const svc = new ValidationService(h.handle.db, new AuditService(h.handle.db));

    // The sensor never answers: the queued row expires and counts as a recent attempt.
    expect(await svc.runSchedules(new Date(Date.now() + 86_400_000))).toEqual({
      queued: 0,
      skipped: 1,
      errors: 0,
    });
    const list = (await jsonOf(
      await get('/api/v1/detection-rules/validations?limit=50', blue),
    )) as { items: DetectionValidation[] };
    expect(list.items).toHaveLength(1);
    expect(list.items[0]).toMatchObject({
      status: 'expired',
      verdict: null,
      error: expect.stringContaining('did not report'),
    });
    expect(list.items[0]!.reportedAt).not.toBeNull();
    // Without that stamp the schedule would re-queue on every tick; it only retries once the
    // interval has elapsed since the expired attempt.
    expect(await svc.runSchedules(new Date(Date.now() + 2 * 86_400_000))).toEqual({
      queued: 0,
      skipped: 1,
      errors: 0,
    });
    expect(await svc.runSchedules(new Date(Date.now() + 8 * 86_400_000))).toEqual({
      queued: 1,
      skipped: 0,
      errors: 0,
    });
  });

  it('stands down while another instance holds the scheduler lock and picks up on the next tick', async () => {
    const s = await enrol('ids-edge-1');
    const ruleId = await importDeployRule();
    const created = await post('/api/v1/detection-rules/validation-schedules', blue, {
      ruleId,
      sensorId: s.id,
      sampleRef: 'c2-beacon.pcap',
      intervalDays: 7,
    });
    expect(created.status).toBe(201);
    const svc = new ValidationService(h.handle.db, new AuditService(h.handle.db));
    // Prove the first run so the schedule is due, with nothing queued.
    const bundle = await jsonOf(
      await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor(s.cred) }),
    );
    const [first] = (
      await jsonOf(await h.app.request('/api/v1/agents/validations', { headers: asSensor(s.cred) }))
    ).items as Array<{ id: string }>;
    await h.app.request(`/api/v1/agents/validations/${first!.id}/result`, {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({
        firedSids: [9000001],
        rulesBundleSha256: bundle.bundleSha256,
        engineVersion: '7.0.6',
        error: null,
        durationMs: 5,
      }),
    });
    const due = new Date(Date.now() + 8 * 86_400_000);

    // Hold the lock on another pooled connection — that is a second API instance mid-pass.
    await h.handle.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_try_advisory_lock(${SCHEDULE_LOCK_KEY}) as locked`);
      expect(await svc.runSchedules(due)).toEqual({ queued: 0, skipped: 0, errors: 0 });
      await tx.execute(sql`select pg_advisory_unlock(${SCHEDULE_LOCK_KEY})`);
    });
    // Released: the same tick now does the work the locked instance stood down from.
    expect(await svc.runSchedules(due)).toEqual({ queued: 1, skipped: 0, errors: 0 });
  });
});
