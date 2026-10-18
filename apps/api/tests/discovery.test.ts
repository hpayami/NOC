import net from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import pino from 'pino';
import { AssetService } from '../src/assets/service';
import { AuditService } from '../src/audit/service';
import { DiscoveryService } from '../src/discovery/service';
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
let admin: { token: string; user: { id: string } };
let red: { token: string; id: string };
let sec: { token: string; id: string };
let analyst: string;
const PW = 'discovery-password-that-is-long';
const hourAgo = () => new Date(Date.now() - 3600_000).toISOString();
const hourAhead = () => new Date(Date.now() + 3600_000).toISOString();

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, network_segments, discovery_jobs, discovery_job_targets cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  const r = await createUser(h, admin.token, {
    email: 'red@test.local',
    password: PW,
    roles: ['red_team_operator'],
  });
  const s = await createUser(h, admin.token, {
    email: 'sec@test.local',
    password: PW,
    roles: ['security_admin'],
  });
  await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  red = { token: (await login(h, 'red@test.local', PW)).body.accessToken, id: r.body.id };
  sec = { token: (await login(h, 'sec@test.local', PW)).body.accessToken, id: s.body.id };
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  // Segments: loopback lab allows active discovery; a management range does not.
  for (const seg of [
    {
      name: 'lab-loopback',
      site: 'lab',
      cidr: '127.0.0.0/8',
      vlanId: null,
      activeDiscoveryAllowed: true,
      description: null,
    },
    {
      name: 'mgmt',
      site: 'hq',
      cidr: '10.99.0.0/16',
      vlanId: 99,
      activeDiscoveryAllowed: false,
      description: null,
    },
  ]) {
    expect(
      (
        await h.app.request('/api/v1/network/segments', {
          method: 'POST',
          headers: authed(admin.token),
          body: JSON.stringify(seg),
        })
      ).status,
    ).toBe(201);
  }
});

const scope = (over: Record<string, unknown> = {}) => ({
  includeCidrs: [],
  includeAddresses: ['127.0.0.1'],
  excludeCidrs: [],
  excludeAddresses: [],
  allowPublicAddresses: false,
  allowedTechniques: ['host_discovery'],
  windowStart: hourAgo(),
  windowEnd: hourAhead(),
  maxConcurrency: 2,
  maxRequestsPerSecond: 50,
  ...over,
});
const createJob = (token: string, body: Record<string, unknown>) =>
  h.app.request('/api/v1/discovery/jobs', {
    method: 'POST',
    headers: authed(token),
    body: JSON.stringify(body),
  });
const decide = (token: string, id: string, decision: string) =>
  h.app.request(`/api/v1/discovery/jobs/${id}/decision`, {
    method: 'POST',
    headers: authed(token),
    body: JSON.stringify({ decision, note: 'Change ticket CHG-1234 approved' }),
  });
const service = () =>
  new DiscoveryService(
    h.handle.db,
    new AuditService(h.handle.db),
    new AssetService(h.handle.db, new AuditService(h.handle.db)),
    pino({ level: 'silent' }),
  );
const actor = (userId: string) => ({ userId, label: 'test', requestId: null, ip: null });

function listen(): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve) => {
    const server = net.createServer((s) => s.end());
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, port: (server.address() as net.AddressInfo).port }),
    );
  });
}

describe('approval-gated active discovery', () => {
  it('rejects scopes that violate policy before anything is stored', async () => {
    expect((await createJob(analyst, { name: 'x', scope: scope() })).status).toBe(403);
    expect(
      (
        await createJob(red.token, {
          name: 'mgmt',
          scope: scope({ includeAddresses: ['10.99.1.1'] }),
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await createJob(red.token, {
          name: 'public',
          scope: scope({ includeAddresses: ['8.8.8.8'] }),
        })
      ).status,
    ).toBe(422);
    expect(
      (await createJob(red.token, { name: 'flag', scope: scope({ allowPublicAddresses: true }) }))
        .status,
    ).toBe(422);
    expect(
      (
        await createJob(red.token, {
          name: 'huge',
          scope: scope({ includeCidrs: ['127.0.0.0/16'], includeAddresses: [] }),
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await createJob(red.token, {
          name: 'intrusive',
          scope: scope({ allowedTechniques: ['vulnerability_scan'] }),
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await createJob(red.token, {
          name: 'expired',
          scope: scope({ windowStart: '2026-01-01T00:00:00Z', windowEnd: '2026-01-02T00:00:00Z' }),
        })
      ).status,
    ).toBe(422);
    expect((await createJob(red.token, { name: 'ports', scope: scope(), ports: [] })).status).toBe(
      400,
    );
    expect(
      await jsonOf(await h.app.request('/api/v1/discovery/jobs', { headers: authed(analyst) })),
    ).toEqual([]);
  });

  it('enforces the two-person rule and the state machine', async () => {
    const job = await jsonOf(
      await createJob(red.token, { name: 'lab sweep', dryRun: true, scope: scope() }),
    );
    expect(job.status).toBe('pending_approval');
    expect(job.targetCount).toBe(1);
    expect(
      (
        await h.app.request(`/api/v1/discovery/jobs/${job.id}/run`, {
          method: 'POST',
          headers: authed(red.token),
        })
      ).status,
    ).toBe(409);
    expect((await decide(red.token, job.id, 'approved')).status).toBe(403); // red lacks approve permission
    // A requester holding approve rights still cannot approve their own job (worker-side rule).
    await expect(
      service().decide(job.id, 'approved', 'self approval attempt here', actor(red.id)),
    ).rejects.toMatchObject({ status: 403 });
    expect((await decide(sec.token, job.id, 'approved')).status).toBe(200);
    expect((await decide(sec.token, job.id, 'approved')).status).toBe(409);
    expect(
      (
        await h.app.request(`/api/v1/discovery/jobs/${job.id}/run`, {
          method: 'POST',
          headers: authed(sec.token),
        })
      ).status,
    ).toBe(403); // approver cannot run
    const rejected = await jsonOf(await createJob(red.token, { name: 'nope', scope: scope() }));
    expect((await jsonOf(await decide(sec.token, rejected.id, 'rejected'))).status).toBe(
      'rejected',
    );
    const audits = (await h.handle.db.execute(
      sql`select action, outcome from audit_events where action like 'discovery.%' order by seq`,
    )) as unknown as Array<{ action: string; outcome: string }>;
    expect(audits.map((a) => `${a.action}:${a.outcome}`)).toEqual(
      expect.arrayContaining([
        'discovery.job_request:success',
        'discovery.job_decision:denied',
        'discovery.job_decision:success',
      ]),
    );
  });

  it('dry runs record per-target decisions and never touch the network or inventory', async () => {
    const job = await jsonOf(
      await createJob(red.token, {
        name: 'dry',
        dryRun: true,
        scope: scope({
          includeAddresses: ['127.0.0.1', '127.0.0.2'],
          excludeAddresses: ['127.0.0.2'],
        }),
      }),
    );
    await decide(sec.token, job.id, 'approved');
    const svc = service();
    await svc.claim(job.id, actor(red.id));
    const summary = await svc.runJob(job.id, actor(red.id));
    expect(summary).toMatchObject({
      allowed: 1,
      denied: 0,
      skipped: 1,
      reachable: 0,
      observationsCreated: 0,
    });
    const detail = await jsonOf(
      await h.app.request(`/api/v1/discovery/jobs/${job.id}`, { headers: authed(analyst) }),
    );
    expect(detail.job.status).toBe('completed');
    expect(detail.targets).toEqual([
      expect.objectContaining({ target: '127.0.0.1', decision: 'allowed', outcome: 'skipped' }),
    ]);
    expect(
      (await jsonOf(await h.app.request('/api/v1/assets', { headers: authed(analyst) }))).items,
    ).toHaveLength(0);
  });

  it('a live run probes only approved ports, creates an observation and respects the window', async () => {
    const { server, port } = await listen();
    try {
      const job = await jsonOf(
        await createJob(red.token, {
          name: 'live',
          dryRun: false,
          scope: scope(),
          ports: [port, 1],
        }),
      );
      await decide(sec.token, job.id, 'approved');
      const svc = service();
      await svc.claim(job.id, actor(red.id));
      const summary = await svc.runJob(job.id, actor(red.id));
      expect(summary).toMatchObject({
        allowed: 1,
        reachable: 1,
        unreachable: 0,
        observationsCreated: 1,
      });
      const detail = await jsonOf(
        await h.app.request(`/api/v1/discovery/jobs/${job.id}`, { headers: authed(analyst) }),
      );
      expect(detail.targets[0].openPorts).toEqual([port]);
      const assets = await jsonOf(
        await h.app.request('/api/v1/assets', { headers: authed(analyst) }),
      );
      expect(assets.items).toHaveLength(1);
      expect(assets.items[0].ipAddresses).toEqual(['127.0.0.1']);
      expect(assets.items[0].discoveryMethods).toEqual(['tcp_service_check']);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('denies targets at run time when the window has closed, even for an approved job', async () => {
    const job = await jsonOf(
      await createJob(red.token, {
        name: 'closing',
        dryRun: false,
        scope: scope({ windowEnd: new Date(Date.now() + 1500).toISOString() }),
      }),
    );
    await decide(sec.token, job.id, 'approved');
    await new Promise((r) => setTimeout(r, 1600));
    const svc = service();
    await svc.claim(job.id, actor(red.id));
    const summary = await svc.runJob(job.id, actor(red.id));
    expect(summary.denied).toBe(1);
    expect(summary.reachable).toBe(0);
  });

  it('cancellation is honoured', async () => {
    const job = await jsonOf(await createJob(red.token, { name: 'cancel', scope: scope() }));
    await decide(sec.token, job.id, 'approved');
    expect(
      (
        await h.app.request(`/api/v1/discovery/jobs/${job.id}/cancel`, {
          method: 'POST',
          headers: authed(analyst),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/discovery/jobs/${job.id}/cancel`, {
            method: 'POST',
            headers: authed(sec.token),
          }),
        )
      ).status,
    ).toBe('cancelled');
    expect(
      (
        await h.app.request(`/api/v1/discovery/jobs/${job.id}/run`, {
          method: 'POST',
          headers: authed(red.token),
        })
      ).status,
    ).toBe(409);
  });
});
