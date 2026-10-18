import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import pino from 'pino';
import { IpsWatchdog } from '../src/ips/service';
import { IpsPolicy, PlatformStatus, SensorIpsDirective } from '@noc/shared';
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
let blue: string; // blue_team_engineer: ips.propose, ips.enable, detection_rules.change
let blue2: string; // second blue engineer (enabler who did not propose — not required, but used for SoD cases)
let sec1: string; // security_admin: ips.approve
let sec2: string;
let auditor: string; // ips.read only
let sensor: { id: string; cred: string };
let ruleId: string;
const PW = 'ips-password-that-is-long-enough';

const post = (path: string, token: string, body: unknown = {}) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });
const asSensor = (cred: string) => ({
  'x-sensor-credential': cred,
  'content-type': 'application/json',
});

async function enrolSuricata(name: string) {
  const id = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name,
        kind: 'suricata',
        site: 'dc1',
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    )
  ).id;
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
  ).credential;
  return { id, cred };
}

const heartbeat = (cred: string, over: Record<string, unknown> = {}) =>
  h.app.request('/api/v1/agents/heartbeat', {
    method: 'POST',
    headers: asSensor(cred),
    body: JSON.stringify({ state: 'healthy', inlineCapable: true, ...over }),
  });

const proposal = (over: Record<string, unknown> = {}) => ({
  name: 'Drop validated C2 to server VLAN',
  sensorId: sensor.id,
  mode: 'ips_test',
  protectedCidrs: ['10.20.0.0/16'],
  excludedCidrs: ['10.20.0.1/32'],
  ruleIds: [ruleId],
  justification: 'ET C2 signature validated against a week of traffic without false positives',
  rollbackPlan: 'Disable the policy; sensor returns to detect-only on its next directive fetch',
  ...over,
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
    ['blue2@test.local', 'blue_team_engineer'],
    ['sec1@test.local', 'security_admin'],
    ['sec2@test.local', 'security_admin'],
    ['auditor@test.local', 'read_only_auditor'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  const t = await Promise.all(
    ['blue', 'blue2', 'sec1', 'sec2', 'auditor'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  );
  [blue, blue2, sec1, sec2, auditor] = t as [string, string, string, string, string];
  sensor = await enrolSuricata('ids-edge-1');
  const imp = await jsonOf(
    await post('/api/v1/detection-rules/import', blue, {
      source: 'custom',
      ruleSet: 'c2',
      license: 'MIT',
      content:
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"CUSTOM C2 beacon"; sid:9000001; rev:1; classtype:trojan-activity;)\n',
    }),
  );
  expect(imp.imported).toBe(1);
  ruleId = (
    await jsonOf(
      await h.app.request('/api/v1/detection-rules?q=9000001', { headers: authed(blue) }),
    )
  ).items[0].id;
});

describe('inline prevention policy plane', () => {
  it('refuses unsafe proposals: public ranges, unvalidated rules, non-Suricata sensors, permissions', async () => {
    expect((await post('/api/v1/ips/policies', auditor, proposal())).status).toBe(403);
    expect((await post('/api/v1/ips/policies', sec1, proposal())).status).toBe(403); // approvers cannot propose
    expect(
      (await post('/api/v1/ips/policies', blue, proposal({ protectedCidrs: ['203.0.113.0/24'] })))
        .status,
    ).toBe(400);
    expect((await post('/api/v1/ips/policies', blue, proposal({ mode: 'ids' }))).status).toBe(400);
    const r = await post('/api/v1/ips/policies', blue, proposal());
    expect(r.status).toBe(409); // rule is still draft
    expect((await jsonOf(r)).error.message).toMatch(/draft/);
    await post(`/api/v1/detection-rules/${ruleId}/validate`, blue);
    const zeek = (
      await jsonOf(
        await post('/api/v1/sensors', admin.token, {
          name: 'zeek-1',
          kind: 'zeek',
          site: 'dc1',
          monitoredSegmentIds: [],
          engineVersion: null,
        }),
      )
    ).id;
    expect((await post('/api/v1/ips/policies', blue, proposal({ sensorId: zeek }))).status).toBe(
      409,
    );
    const ok = await post('/api/v1/ips/policies', blue, proposal());
    expect(ok.status).toBe(201);
    const p = IpsPolicy.parse(await jsonOf(ok));
    expect(p).toMatchObject({
      status: 'pending_approval',
      requiredApprovals: 2,
      version: 0,
      applyState: 'none',
      sensorName: 'ids-edge-1',
    });
    // The sensor is untouched: its directive is detect-only and fail-open.
    const d = SensorIpsDirective.parse(
      await jsonOf(
        await h.app.request('/api/v1/agents/ips-directive', { headers: asSensor(sensor.cred) }),
      ),
    );
    expect(d).toMatchObject({ mode: 'ids', policyId: null, failOpen: true });
  });

  it('needs two independent approvals, a healthy inline-capable sensor and a non-approver to enable; then expires and acks', async () => {
    await post(`/api/v1/detection-rules/${ruleId}/validate`, blue);
    const p = IpsPolicy.parse(await jsonOf(await post('/api/v1/ips/policies', blue, proposal())));
    const enable = (token: string, hours = 2) =>
      post(`/api/v1/ips/policies/${p.id}/enable`, token, { enabledForHours: hours });
    const status = async () =>
      (
        await jsonOf(
          await h.app.request(`/api/v1/ips/policies/${p.id}`, { headers: authed(auditor) }),
        )
      ).status;

    expect((await enable(blue)).status).toBe(409); // not approved
    expect(
      (await post(`/api/v1/ips/policies/${p.id}/approve`, blue, { justification: 'self' })).status,
    ).toBe(403); // no ips.approve
    expect(
      (
        await jsonOf(
          await post(`/api/v1/ips/policies/${p.id}/approve`, sec1, {
            justification: 'Scope is the server VLAN only; rule validated',
          }),
        )
      ).status,
    ).toBe('pending_approval');
    expect(
      (await post(`/api/v1/ips/policies/${p.id}/approve`, sec1, { justification: 'again' })).status,
    ).toBe(409);
    expect((await enable(blue)).status).toBe(409); // one of two approvals
    expect(
      (
        await jsonOf(
          await post(`/api/v1/ips/policies/${p.id}/approve`, sec2, {
            justification: 'Concur; change window agreed',
          }),
        )
      ).status,
    ).toBe('approved');

    // Sensor gates: silent → heartbeat but not inline-capable → degraded → healthy+capable.
    // (Enrolment records a heartbeat, so silence is forced by ageing it.)
    await h.handle.db.execute(
      sql`update sensors set last_heartbeat_at = now() - interval '10 minutes' where id = ${sensor.id}`,
    );
    let r = await enable(blue);
    expect(r.status).toBe(409);
    expect((await jsonOf(r)).error.message).toMatch(/heartbeat/);
    await heartbeat(sensor.cred, { inlineCapable: false });
    r = await enable(blue);
    expect((await jsonOf(r)).error.message).toMatch(/inline capability/);
    await heartbeat(sensor.cred, { state: 'degraded' });
    r = await enable(blue);
    expect((await jsonOf(r)).error.message).toMatch(/degraded/);
    await heartbeat(sensor.cred);
    expect((await enable(blue, 100)).status).toBe(400); // TTL bound
    const on = IpsPolicy.parse(await jsonOf(await enable(blue)));
    expect(on).toMatchObject({
      status: 'enabled',
      version: 1,
      applyState: 'pending',
      enabledBy: expect.any(String),
    });
    expect(new Date(on.expiresAt!).getTime() - Date.now()).toBeLessThanOrEqual(2 * 3_600_000);
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/sensors/${sensor.id}/status`, {
            headers: authed(admin.token),
          }),
        )
      ).sensor.mode,
    ).toBe('inline_prevention');

    // The sensor now receives the policy and acknowledges it; platform status reflects it.
    const d = SensorIpsDirective.parse(
      await jsonOf(
        await h.app.request('/api/v1/agents/ips-directive', { headers: asSensor(sensor.cred) }),
      ),
    );
    expect(d).toMatchObject({
      mode: 'ips_test',
      policyId: p.id,
      version: 1,
      protectedCidrs: ['10.20.0.0/16'],
      excludedCidrs: ['10.20.0.1/32'],
      ruleRefs: ['1:9000001'],
      failOpen: true,
    });
    let st = PlatformStatus.parse(
      await jsonOf(
        await h.app.request('/api/v1/platform/status', { headers: authed(admin.token) }),
      ),
    );
    expect(st.capabilities.find((c) => c.id === 'nips.inline_prevention')).toMatchObject({
      state: 'degraded',
    }); // enabled, not yet acknowledged
    expect(
      (
        await h.app.request('/api/v1/agents/ips-ack', {
          method: 'POST',
          headers: asSensor(sensor.cred),
          body: JSON.stringify({ policyId: p.id, version: 1, applied: true }),
        })
      ).status,
    ).toBe(204);
    expect(
      await jsonOf(
        await h.app.request(`/api/v1/ips/policies/${p.id}`, { headers: authed(auditor) }),
      ),
    ).toMatchObject({ applyState: 'applied', appliedVersion: 1 });
    st = PlatformStatus.parse(
      await jsonOf(
        await h.app.request('/api/v1/platform/status', { headers: authed(admin.token) }),
      ),
    );
    expect(st.capabilities.find((c) => c.id === 'nips.inline_prevention')?.state).toBe('available');

    // A second policy on the same sensor cannot be enabled while one is live.
    const p2 = IpsPolicy.parse(
      await jsonOf(await post('/api/v1/ips/policies', blue2, proposal({ name: 'second' }))),
    );
    await post(`/api/v1/ips/policies/${p2.id}/approve`, sec1, { justification: 'ok for later' });
    await post(`/api/v1/ips/policies/${p2.id}/approve`, sec2, { justification: 'ok for later' });
    expect(
      (
        await jsonOf(
          await post(`/api/v1/ips/policies/${p2.id}/enable`, blue, { enabledForHours: 1 }),
        )
      ).error.message,
    ).toMatch(/Another policy/);

    // Kill switch by an approver (no approval needed), sensor returns to detect-only and acks the version.
    expect(
      (await post(`/api/v1/ips/policies/${p.id}/disable`, auditor, { reason: 'panic' })).status,
    ).toBe(403);
    const off = IpsPolicy.parse(
      await jsonOf(
        await post(`/api/v1/ips/policies/${p.id}/disable`, sec1, {
          reason: 'False positives on backup traffic',
        }),
      ),
    );
    expect(off).toMatchObject({ status: 'disabled', version: 2, applyState: 'pending' });
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/sensors/${sensor.id}/status`, {
            headers: authed(admin.token),
          }),
        )
      ).sensor.mode,
    ).toBe('out_of_band');
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/ips-directive', { headers: asSensor(sensor.cred) }),
        )
      ).mode,
    ).toBe('ids');
    await h.app.request('/api/v1/agents/ips-ack', {
      method: 'POST',
      headers: asSensor(sensor.cred),
      body: JSON.stringify({ policyId: null, version: 2, applied: true }),
    });
    expect(await status()).toBe('disabled');
    expect(
      await jsonOf(
        await h.app.request(`/api/v1/ips/policies/${p.id}`, { headers: authed(auditor) }),
      ),
    ).toMatchObject({ appliedVersion: 2 });

    // TTL: an enabled policy past its expiry is expired on the sensor's next fetch (fail-safe).
    await heartbeat(sensor.cred);
    const live = IpsPolicy.parse(
      await jsonOf(
        await post(`/api/v1/ips/policies/${p2.id}/enable`, blue, { enabledForHours: 1 }),
      ),
    );
    expect(live.status).toBe('enabled');
    await h.handle.db.execute(
      sql`update ips_policies set expires_at = now() - interval '1 second' where id = ${p2.id}`,
    );
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/ips-directive', { headers: asSensor(sensor.cred) }),
        )
      ).mode,
    ).toBe('ids');
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/ips/policies/${p2.id}`, { headers: authed(auditor) }),
        )
      ).status,
    ).toBe('expired');
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/sensors/${sensor.id}/status`, {
            headers: authed(admin.token),
          }),
        )
      ).sensor.mode,
    ).toBe('out_of_band');

    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin.token) }),
    );
    const acts = audit.items.map(
      (e: { action: string; outcome: string }) => `${e.action}:${e.outcome}`,
    );
    expect(acts).toEqual(
      expect.arrayContaining([
        'ips.propose:success',
        'ips.approve:success',
        'ips.enable:failure',
        'ips.enable:success',
        'ips.disable:success',
        'ips.expire:success',
      ]),
    );
    expect(audit.items.find((e: { action: string }) => e.action === 'ips.expire').actorLabel).toBe(
      'system:ips',
    );
  });

  it('returns a sensor to detect-only on its own when it degrades or goes silent while inline', async () => {
    await post(`/api/v1/detection-rules/${ruleId}/validate`, blue);
    const approveAndEnable = async (name: string) => {
      const p = IpsPolicy.parse(
        await jsonOf(await post('/api/v1/ips/policies', blue, proposal({ name }))),
      );
      for (const [tok, why] of [
        [sec1, 'Scope is the server VLAN only; rule validated'],
        [sec2, 'Concur; change window agreed'],
      ] as const)
        await post(`/api/v1/ips/policies/${p.id}/approve`, tok, { justification: why });
      await heartbeat(sensor.cred);
      const live = IpsPolicy.parse(
        await jsonOf(
          await post(`/api/v1/ips/policies/${p.id}/enable`, blue, { enabledForHours: 4 }),
        ),
      );
      expect(live.status).toBe('enabled');
      return p.id;
    };
    const policy = async (id: string) =>
      jsonOf(await h.app.request(`/api/v1/ips/policies/${id}`, { headers: authed(auditor) }));
    const sensorMode = async () =>
      (
        await jsonOf(
          await h.app.request(`/api/v1/sensors/${sensor.id}/status`, {
            headers: authed(admin.token),
          }),
        )
      ).sensor.mode;
    const directive = async () =>
      (
        await jsonOf(
          await h.app.request('/api/v1/agents/ips-directive', { headers: asSensor(sensor.cred) }),
        )
      ).mode;

    // 1. Degraded heartbeat while inline: dropped at the heartbeat, before any directive fetch.
    const first = await approveAndEnable('watchdog-degraded');
    expect(await sensorMode()).toBe('inline_prevention');
    expect((await heartbeat(sensor.cred, { state: 'degraded' })).status).toBe(204);
    expect(await policy(first)).toMatchObject({
      status: 'disabled',
      disableCause: 'sensor_unhealthy',
      disabledBy: null,
    });
    expect((await policy(first)).disableReason).toMatch(/sensor_unhealthy/);
    expect(await sensorMode()).toBe('out_of_band');
    expect(await directive()).toBe('ids');

    // 2. Lost inline capability: same outcome.
    const second = await approveAndEnable('watchdog-capability');
    await heartbeat(sensor.cred, { inlineCapable: false });
    expect(await policy(second)).toMatchObject({
      status: 'disabled',
      disableCause: 'sensor_unhealthy',
    });
    expect((await policy(second)).disableReason).toMatch(/not_inline_capable/);

    // 3. Silence: no heartbeat arrives to trigger anything, so the watchdog tick must catch it.
    const third = await approveAndEnable('watchdog-silent');
    await h.handle.db.execute(
      sql`update sensors set last_heartbeat_at = now() - interval '10 minutes' where id = ${sensor.id}`,
    );
    expect(await policy(third)).toMatchObject({ status: 'enabled' }); // nothing ran yet
    const watchdog = new IpsWatchdog(h.ips, {
      intervalSeconds: 60,
      logger: pino({ level: 'silent' }),
    });
    expect(await watchdog.tick()).toEqual({ expired: 0, autoDisabled: 1 });
    expect(await policy(third)).toMatchObject({
      status: 'disabled',
      disableCause: 'sensor_unhealthy',
    });
    expect((await policy(third)).disableReason).toMatch(/sensor_silent/);
    expect(await watchdog.tick()).toEqual({ expired: 0, autoDisabled: 0 }); // idempotent

    // 4. A healthy, heartbeating sensor is left alone; a manual kill switch keeps cause=manual.
    const fourth = await approveAndEnable('watchdog-healthy');
    expect(await watchdog.tick()).toEqual({ expired: 0, autoDisabled: 0 });
    expect(await policy(fourth)).toMatchObject({ status: 'enabled' });
    await post(`/api/v1/ips/policies/${fourth}/disable`, sec1, { reason: 'Change window closed' });
    expect(await policy(fourth)).toMatchObject({ status: 'disabled', disableCause: 'manual' });

    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin.token) }),
    );
    const auto = audit.items.filter((e: { action: string }) => e.action === 'ips.auto_disable');
    expect(auto).toHaveLength(3);
    expect(auto.every((e: { actorLabel: string }) => e.actorLabel === 'system:ips')).toBe(true);
    expect(auto.map((e: { metadata: { cause: string } }) => e.metadata.cause)).toEqual([
      'sensor_unhealthy',
      'sensor_unhealthy',
      'sensor_unhealthy',
    ]);
  });
});
