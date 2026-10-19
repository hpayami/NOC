import http from 'node:http';
import net from 'node:net';
import { createHmac } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { PlatformConditions, WebhookPayload } from '@noc/shared';
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
let blue: string; // blue_team_engineer: platform.status.read, no notifications.manage
const PW = 'operations-password-long-enough-42';

interface Received {
  headers: http.IncomingHttpHeaders;
  body: string;
}
/** Webhook receiver: records every request; answers 500 while `fail` is set. */
function receiver(): Promise<{
  server: http.Server;
  url: string;
  got: Received[];
  state: { fail: boolean };
}> {
  const got: Received[] = [];
  const state = { fail: false };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      got.push({ headers: req.headers, body });
      res.statusCode = state.fail ? 500 : 204;
      res.end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({ server, url: `http://127.0.0.1:${port}/hook`, got, state });
    });
  });
}

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
  // Enrolment stamps a heartbeat; a sensor that then never reports is what 'silent' means.
  await h.handle.db.execute(
    sql`update sensors set enabled = true, last_heartbeat_at = null where id = ${id}`,
  );
  return { id, cred };
}

interface MailSeen {
  auth: string | null;
  from: string | null;
  to: string[];
  data: string;
}
/** Minimal SMTP stub: EHLO/AUTH PLAIN/MAIL/RCPT/DATA/QUIT; `rejectRcpt` answers 550 to recipients. */
function smtpStub(): Promise<{
  server: net.Server;
  port: number;
  mails: MailSeen[];
  state: { rejectRcpt: boolean };
}> {
  const mails: MailSeen[] = [];
  const state = { rejectRcpt: false };
  const server = net.createServer((sock) => {
    let buf = '';
    let inData = false;
    let cur: MailSeen = { auth: null, from: null, to: [], data: '' };
    const send = (l: string) => sock.write(l + '\r\n');
    send('220 stub ESMTP');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      for (;;) {
        const i = buf.indexOf('\r\n');
        if (i < 0) break;
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            mails.push(cur);
            cur = { auth: null, from: null, to: [], data: '' };
            send('250 2.0.0 Ok: queued as 42');
          } else cur.data += line + '\n';
          continue;
        }
        const up = line.toUpperCase();
        if (up.startsWith('EHLO')) {
          send('250-stub');
          send('250 AUTH PLAIN LOGIN');
        } else if (up.startsWith('AUTH PLAIN')) {
          cur.auth = Buffer.from(line.slice(11), 'base64').toString('utf8');
          send('235 2.7.0 Authentication successful');
        } else if (up.startsWith('MAIL FROM:')) {
          cur.from = line.slice(10).replace(/[<>]/g, '');
          send('250 2.1.0 Ok');
        } else if (up.startsWith('RCPT TO:')) {
          if (state.rejectRcpt) send('550 5.1.1 User unknown');
          else {
            cur.to.push(line.slice(8).replace(/[<>]/g, ''));
            send('250 2.1.5 Ok');
          }
        } else if (up === 'DATA') {
          inData = true;
          send('354 End data with <CR><LF>.<CR><LF>');
        } else if (up === 'QUIT') {
          send('221 2.0.0 Bye');
          sock.end();
        } else send('500 5.5.1 Unknown command');
      }
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, port: (server.address() as { port: number }).port, mails, state }),
    ),
  );
}

let hook: Awaited<ReturnType<typeof receiver>>;
let smtp: Awaited<ReturnType<typeof smtpStub>>;
beforeAll(async () => {
  h = await createHarness();
  hook = await receiver();
  smtp = await smtpStub();
});
afterAll(async () => {
  hook.server.close();
  smtp.server.close();
  await h.close();
});
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table sensor_health, sensors, notification_deliveries, notification_states cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'blue@test.local',
    password: PW,
    roles: ['blue_team_engineer'],
  });
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken as string;
  hook.got.length = 0;
  hook.state.fail = false;
  smtp.mails.length = 0;
  smtp.state.rejectRcpt = false;
});

const SECRET = 'webhook-shared-secret-0123456789';

describe('platform conditions and notifications', () => {
  it('reports every check, raises conditions from real records and resolves them when records change', async () => {
    // Empty platform: nothing raised except the analysis service, which really is unreachable here.
    const quiet = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', blue)),
    );
    expect(quiet.checks.map((c) => c.id).sort()).toEqual(
      [
        'analysis_reachable',
        'approvals_pending',
        'assets_unmonitored',
        'cves_uncatalogued',
        'ips_auto_disabled',
        'ips_policies_expiring',
        'rule_bundles_out_of_sync',
        'sensors_silent',
        'sensors_unhealthy',
      ].sort(),
    );
    expect(quiet.conditions.map((c) => c.id)).toEqual(['analysis_unreachable']);
    expect(quiet.checks.find((c) => c.id === 'sensors_silent')).toMatchObject({
      status: 'ok',
      detail: '0 enabled sensor(s) heartbeating',
    });

    // An enabled sensor that never heartbeat is silent and is not running any bundle.
    const s = await enrol('ids-edge-1');
    const raised = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', admin.token)),
    );
    expect(raised.conditions.map((c) => [c.id, c.severity, c.count])).toEqual([
      ['sensors_silent', 'critical', 1],
      ['analysis_unreachable', 'warning', 1],
      ['rule_bundles_out_of_sync', 'warning', 1],
    ]);
    expect(raised.conditions[0]!.detail).toContain('ids-edge-1');
    expect(raised.conditions[0]!.link).toBe('/nids');

    // Heartbeat carrying the current bundle digest clears both sensor conditions.
    const bundle = await jsonOf(
      await h.app.request('/api/v1/agents/rules-bundle', { headers: asSensor(s.cred) }),
    );
    const hb = await h.app.request('/api/v1/agents/heartbeat', {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ state: 'healthy', rulesBundleSha256: bundle.bundleSha256 }),
    });
    expect(hb.status).toBe(204);
    const after = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', admin.token)),
    );
    expect(after.conditions.map((c) => c.id)).toEqual(['analysis_unreachable']);

    // Degraded health is a warning, distinct from silence.
    const dh = await h.app.request('/api/v1/agents/heartbeat', {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ state: 'degraded', rulesBundleSha256: bundle.bundleSha256 }),
    });
    expect(dh.status).toBe(204);
    const degraded = PlatformConditions.parse(
      await jsonOf(await get('/api/v1/operations/conditions', admin.token)),
    );
    expect(degraded.conditions.map((c) => c.id)).toContain('sensors_unhealthy');
    expect(degraded.conditions.map((c) => c.id)).not.toContain('sensors_silent');
  });

  it('manages channels under notifications.manage, never returns the secret and validates the URL', async () => {
    expect((await get('/api/v1/operations/channels', blue)).status).toBe(403);
    expect(
      (
        await post('/api/v1/operations/channels', blue, {
          name: 'x',
          url: hook.url,
          secret: SECRET,
        })
      ).status,
    ).toBe(403);
    const bad = await post('/api/v1/operations/channels', admin.token, {
      name: 'x',
      url: 'ftp://hooks.example/x',
      secret: SECRET,
    });
    expect(bad.status).toBe(400);
    const short = await post('/api/v1/operations/channels', admin.token, {
      name: 'x',
      url: hook.url,
      secret: 'short',
    });
    expect(short.status).toBe(400);

    const created = await post('/api/v1/operations/channels', admin.token, {
      name: 'ops-room',
      url: hook.url,
      secret: SECRET,
    });
    expect(created.status).toBe(201);
    const ch = await jsonOf(created);
    expect(ch).toMatchObject({
      name: 'ops-room',
      kind: 'webhook',
      enabled: true,
      minSeverity: 'warning',
      lastStatus: null,
    });
    expect(ch).not.toHaveProperty('secret');
    const listed = await jsonOf(await get('/api/v1/operations/channels', admin.token));
    expect(listed.items).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain(SECRET);

    const patched = await h.app.request(`/api/v1/operations/channels/${ch.id}`, {
      method: 'PATCH',
      headers: authed(admin.token),
      body: JSON.stringify({ minSeverity: 'critical', enabled: false }),
    });
    expect(patched.status).toBe(200);
    expect(await jsonOf(patched)).toMatchObject({ minSeverity: 'critical', enabled: false });
    expect(
      (
        await h.app.request('/api/v1/operations/channels/00000000-0000-4000-8000-000000000000', {
          method: 'PATCH',
          headers: authed(admin.token),
          body: JSON.stringify({ enabled: true }),
        })
      ).status,
    ).toBe(404);

    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    const actions = (audit.items as Array<{ action: string }>).map((a) => a.action);
    expect(actions).toContain('notifications.channel_create');
    expect(actions).toContain('notifications.channel_update');
  });

  it('delivers signed webhooks once per condition change, reminds after the quiet period, resolves, and retries failures', async () => {
    const s = await enrol('ids-edge-1');
    const ch = await jsonOf(
      await post('/api/v1/operations/channels', admin.token, {
        name: 'ops-room',
        url: hook.url,
        secret: SECRET,
        minSeverity: 'critical',
      }),
    );
    const t0 = new Date();

    // First cycle: the silent sensor is critical → one signed 'raised' delivery; warnings are below the floor.
    expect(await h.operations.notify(t0)).toEqual({ raised: 1, resolved: 0, failed: 0 });
    expect(hook.got).toHaveLength(1);
    const first = hook.got[0]!;
    expect(first.headers['x-noc-event']).toBe('raised');
    expect(first.headers['x-noc-signature']).toBe(
      `sha256=${createHmac('sha256', SECRET).update(first.body).digest('hex')}`,
    );
    expect(first.headers['x-noc-timestamp']).toBe(t0.toISOString());
    const payload = WebhookPayload.parse(JSON.parse(first.body));
    expect(payload.condition).toMatchObject({
      id: 'sensors_silent',
      severity: 'critical',
      count: 1,
    });
    expect(payload.platform.service).toBe('noc-api');

    // Same state again: quiet. After the reminder period: raised again, once.
    expect(await h.operations.notify(new Date(t0.getTime() + 60_000))).toEqual({
      raised: 0,
      resolved: 0,
      failed: 0,
    });
    expect(hook.got).toHaveLength(1);
    expect(await h.operations.notify(new Date(t0.getTime() + 7 * 3_600_000))).toEqual({
      raised: 1,
      resolved: 0,
      failed: 0,
    });
    expect(hook.got).toHaveLength(2);

    // Heartbeat resolves the condition → one 'resolved' delivery, then quiet.
    const hb = await h.app.request('/api/v1/agents/heartbeat', {
      method: 'POST',
      headers: asSensor(s.cred),
      body: JSON.stringify({ state: 'healthy' }),
    });
    expect(hb.status).toBe(204);
    // Evaluated at wall-clock time: the heartbeat is fresh, so the condition is gone.
    const t1 = new Date();
    expect(await h.operations.notify(t1)).toEqual({ raised: 0, resolved: 1, failed: 0 });
    expect(hook.got[2]!.headers['x-noc-event']).toBe('resolved');
    expect(WebhookPayload.parse(JSON.parse(hook.got[2]!.body)).condition.id).toBe('sensors_silent');
    expect(await h.operations.notify(new Date(t1.getTime() + 60_000))).toEqual({
      raised: 0,
      resolved: 0,
      failed: 0,
    });

    // Receiver down: the attempt is recorded as failed, the channel shows it, and nothing is marked sent.
    await h.handle.db.execute(
      sql`update sensors set last_heartbeat_at = now() - interval '20 minutes'`,
    );
    hook.state.fail = true;
    const t2 = new Date(t1.getTime() + 2 * 60_000);
    expect(await h.operations.notify(t2)).toEqual({ raised: 0, resolved: 0, failed: 1 });
    const chs = await jsonOf(await get('/api/v1/operations/channels', admin.token));
    expect(chs.items[0]).toMatchObject({ lastStatus: 'failed', lastError: 'HTTP 500' });
    const status = await jsonOf(await get('/api/v1/platform/status', admin.token));
    expect(
      status.capabilities.find((c: { id: string }) => c.id === 'ops.notifications').state,
    ).toBe('degraded');

    // Receiver back: retried on the next cycle, not lost.
    hook.state.fail = false;
    expect(await h.operations.notify(new Date(t2.getTime() + 60_000))).toEqual({
      raised: 1,
      resolved: 0,
      failed: 0,
    });
    expect(
      status.capabilities.find((c: { id: string }) => c.id === 'ops.notifications').state,
    ).toBe('degraded');
    const healthy = await jsonOf(await get('/api/v1/platform/status', admin.token));
    expect(
      healthy.capabilities.find((c: { id: string }) => c.id === 'ops.notifications').state,
    ).toBe('available');

    const deliveries = (await jsonOf(await get('/api/v1/operations/deliveries', admin.token)))
      .items as Array<{
      event: string;
      status: string;
      httpStatus: number | null;
      conditionId: string;
    }>;
    // Newest attempt first; the reminder was stamped 7 h ahead so it sorts to the top.
    expect(deliveries.map((d) => [d.event, d.status, d.httpStatus])).toEqual([
      ['raised', 'sent', 204], // reminder (t0 + 7 h)
      ['raised', 'sent', 204], // retry after the receiver recovered
      ['raised', 'failed', 500],
      ['resolved', 'sent', 204],
      ['raised', 'sent', 204], // first raise (t0)
    ]);
    expect(deliveries.every((d) => d.conditionId === 'sensors_silent')).toBe(true);
    expect((await get('/api/v1/operations/deliveries', blue)).status).toBe(403);

    // A disabled channel receives nothing.
    await h.app.request(`/api/v1/operations/channels/${ch.id}`, {
      method: 'PATCH',
      headers: authed(admin.token),
      body: JSON.stringify({ enabled: false }),
    });
    await h.handle.db.execute(sql`update sensors set last_heartbeat_at = null`);
    expect(await h.operations.notify(new Date(t2.getTime() + 8 * 3_600_000))).toEqual({
      raised: 0,
      resolved: 0,
      failed: 0,
    });
  });

  it('test deliveries are signed, recorded and audited, and report an unreachable receiver honestly', async () => {
    const ch = await jsonOf(
      await post('/api/v1/operations/channels', admin.token, {
        name: 'ops-room',
        url: hook.url,
        secret: SECRET,
      }),
    );
    expect((await post(`/api/v1/operations/channels/${ch.id}/test`, blue)).status).toBe(403);
    const ok = await post(`/api/v1/operations/channels/${ch.id}/test`, admin.token);
    expect(ok.status).toBe(200);
    expect(await jsonOf(ok)).toMatchObject({
      event: 'test',
      status: 'sent',
      httpStatus: 204,
      conditionId: 'test',
    });
    expect(hook.got[0]!.headers['x-noc-event']).toBe('test');
    expect(WebhookPayload.parse(JSON.parse(hook.got[0]!.body)).event).toBe('test');

    const dead = await jsonOf(
      await post('/api/v1/operations/channels', admin.token, {
        name: 'nobody-listens',
        url: 'http://127.0.0.1:9/hook',
        secret: SECRET,
      }),
    );
    const failed = await jsonOf(
      await post(`/api/v1/operations/channels/${dead.id}/test`, admin.token),
    );
    expect(failed).toMatchObject({ event: 'test', status: 'failed', httpStatus: null });
    expect(failed.error).toBeTruthy();
    expect(
      (
        await post(
          '/api/v1/operations/channels/00000000-0000-4000-8000-000000000000/test',
          admin.token,
        )
      ).status,
    ).toBe(404);
    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    expect(
      (audit.items as Array<{ action: string }>).filter(
        (a) => a.action === 'notifications.channel_test',
      ),
    ).toHaveLength(2);
  });

  it('delivers e-mail channels over SMTP with the same state machine, never returning the password', async () => {
    const bad = await post('/api/v1/operations/channels', admin.token, {
      kind: 'email',
      name: 'oncall',
      email: { host: 'mail.example', from: 'noc@example.test', recipients: [] },
    });
    expect(bad.status).toBe(400);
    const created = await post('/api/v1/operations/channels', admin.token, {
      kind: 'email',
      name: 'oncall',
      minSeverity: 'critical',
      email: {
        host: '127.0.0.1',
        port: smtp.port,
        starttls: false,
        username: 'noc-bot',
        from: 'noc@example.test',
        recipients: ['soc@example.test', 'ops@example.test'],
      },
      password: 'smtp-password-0123456789',
    });
    expect(created.status).toBe(201);
    const ch = await jsonOf(created);
    expect(ch).toMatchObject({
      kind: 'email',
      url: null,
      email: {
        host: '127.0.0.1',
        port: smtp.port,
        starttls: false,
        username: 'noc-bot',
        from: 'noc@example.test',
        recipients: ['soc@example.test', 'ops@example.test'],
      },
    });
    expect(JSON.stringify(ch)).not.toContain('smtp-password');
    expect(
      JSON.stringify(await jsonOf(await get('/api/v1/operations/channels', admin.token))),
    ).not.toContain('smtp-password');

    // Test delivery: one authenticated message to both recipients, subject and body from the condition.
    const t = await jsonOf(await post(`/api/v1/operations/channels/${ch.id}/test`, admin.token));
    expect(t).toMatchObject({ event: 'test', status: 'sent', httpStatus: null, error: null });
    expect(smtp.mails).toHaveLength(1);
    const m = smtp.mails[0]!;
    expect(m.auth).toBe('\0noc-bot\0smtp-password-0123456789');
    expect(m.from).toBe('noc@example.test');
    expect(m.to).toEqual(['soc@example.test', 'ops@example.test']);
    expect(m.data).toContain('Subject: [NOC] TEST: Test notification');
    expect(m.data).toContain('Content-Transfer-Encoding: base64');
    const body = Buffer.from(m.data.split('\n\n')[1]!.replace(/\s/g, ''), 'base64').toString(
      'utf8',
    );
    expect(body).toContain('Condition: test');
    expect(body).toContain('nothing is wrong');

    // A critical condition raises once by e-mail; a rejected recipient is a failed delivery that is retried.
    await enrol('ids-edge-1');
    const t0 = new Date();
    expect(await h.operations.notify(t0)).toEqual({ raised: 1, resolved: 0, failed: 0 });
    expect(smtp.mails).toHaveLength(2);
    expect(smtp.mails[1]!.data).toContain('Subject: [NOC] CRITICAL: Sensors silent');
    expect(await h.operations.notify(new Date(t0.getTime() + 60_000))).toEqual({
      raised: 0,
      resolved: 0,
      failed: 0,
    });
    smtp.state.rejectRcpt = true;
    await h.handle.db.execute(
      sql`update sensors set last_heartbeat_at = now() - interval '20 minutes'`,
    );
    const ch2 = await jsonOf(
      await post('/api/v1/operations/channels', admin.token, {
        kind: 'email',
        name: 'second',
        minSeverity: 'critical',
        email: {
          host: '127.0.0.1',
          port: smtp.port,
          starttls: false,
          from: 'noc@example.test',
          recipients: ['nobody@example.test'],
        },
      }),
    );
    expect(await h.operations.notify(new Date(t0.getTime() + 120_000))).toEqual({
      raised: 0,
      resolved: 0,
      failed: 1,
    });
    const chs = (await jsonOf(await get('/api/v1/operations/channels', admin.token)))
      .items as Array<{ id: string; lastStatus: string; lastError: string | null }>;
    expect(chs.find((c) => c.id === ch2.id)).toMatchObject({ lastStatus: 'failed' });
    expect(chs.find((c) => c.id === ch2.id)!.lastError).toContain('550 5.1.1 User unknown');
    smtp.state.rejectRcpt = false;
    expect(await h.operations.notify(new Date(t0.getTime() + 180_000))).toEqual({
      raised: 1,
      resolved: 0,
      failed: 0,
    });
    const status = await jsonOf(await get('/api/v1/platform/status', admin.token));
    expect(
      status.capabilities.find((c: { id: string }) => c.id === 'ops.notifications').state,
    ).toBe('available');
  });
});
