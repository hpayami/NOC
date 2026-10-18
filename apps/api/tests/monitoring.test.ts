import net from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import pino from 'pino';
import { MonitoringOverview } from '@noc/shared';
import { AvailabilityService, MonitoringScheduler } from '../src/monitoring/service';
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
let noc: string; // noc_operator: monitoring.read/manage/ingest, discovery.run_passive, sensors.read
let analyst: string; // soc_analyst: read only
const PW = 'monitoring-password-that-is-long';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, network_segments, monitoring_checks, check_results, maintenance_windows, asset_metrics, sensors, sensor_health cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'noc@test.local',
    password: PW,
    roles: ['noc_operator'],
  });
  await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  noc = (await login(h, 'noc@test.local', PW)).body.accessToken;
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
});

async function createAsset(ip: string, mac = 'aa:bb:cc:dd:ee:01'): Promise<string> {
  const r = await jsonOf(
    await h.app.request('/api/v1/assets/observations', {
      method: 'POST',
      headers: authed(noc),
      body: JSON.stringify({
        source: 't',
        method: 'manual',
        observedAt: '2026-10-18T10:00:00Z',
        identifiers: { macAddresses: [mac], ipAddresses: [ip], hostnames: ['h'] },
        attributes: {},
      }),
    }),
  );
  return r.assetId as string;
}
const createCheck = (token: string, body: Record<string, unknown>) =>
  h.app.request('/api/v1/monitoring/checks', {
    method: 'POST',
    headers: authed(token),
    body: JSON.stringify(body),
  });
const assetStatus = async (id: string) =>
  (await jsonOf(await h.app.request(`/api/v1/assets/${id}`, { headers: authed(analyst) }))).asset
    .operationalStatus as string;

function listen(): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve) => {
    const server = net.createServer((s) => s.end());
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, port: (server.address() as net.AddressInfo).port }),
    );
  });
}

describe('availability monitoring', () => {
  it('enforces RBAC and the target-must-belong-to-asset / no-public rule', async () => {
    const id = await createAsset('127.0.0.1');
    expect(
      (await createCheck(analyst, { assetId: id, kind: 'tcp', target: '127.0.0.1', port: 22 }))
        .status,
    ).toBe(403);
    expect(
      (await createCheck(noc, { assetId: id, kind: 'tcp', target: '10.9.9.9', port: 22 })).status,
    ).toBe(422);
    expect((await createCheck(noc, { assetId: id, kind: 'tcp', target: '127.0.0.1' })).status).toBe(
      400,
    ); // tcp needs a port
    const pub = await createAsset('8.8.8.8', 'aa:bb:cc:dd:ee:02');
    expect(
      (await createCheck(noc, { assetId: pub, kind: 'tcp', target: '8.8.8.8', port: 53 })).status,
    ).toBe(422);
    expect(
      (await createCheck(noc, { assetId: id, kind: 'tcp', target: '127.0.0.1', port: 22 })).status,
    ).toBe(201);
    expect(
      (await h.app.request('/api/v1/monitoring/checks', { headers: authed(analyst) })).status,
    ).toBe(200);
  });

  it('platform TCP checks drive online → offline, and unsupported kinds never fake a result', async () => {
    const { server, port } = await listen();
    const id = await createAsset('127.0.0.1');
    const check = await jsonOf(
      await createCheck(noc, {
        assetId: id,
        kind: 'tcp',
        target: '127.0.0.1',
        port,
        intervalSeconds: 30,
      }),
    );
    expect(check.collectorId).toBeNull();
    const scheduler = new MonitoringScheduler(h.handle.db, new AvailabilityService(h.handle.db), {
      tickSeconds: 15,
      maxConcurrency: 4,
      logger: pino({ level: 'silent' }),
    });

    expect(await scheduler.runDueChecks(new Date())).toBe(1);
    expect(await assetStatus(id)).toBe('online');
    // Not due again until the interval elapses.
    expect(await scheduler.runDueChecks(new Date())).toBe(0);

    await new Promise<void>((r) => server.close(() => r()));
    expect(await scheduler.runDueChecks(new Date(Date.now() + 60_000))).toBe(1);
    expect(await assetStatus(id)).toBe('offline');

    const results = await jsonOf(
      await h.app.request(`/api/v1/monitoring/checks/${check.id}/results`, {
        headers: authed(analyst),
      }),
    );
    expect(results.map((r: { outcome: string }) => r.outcome)).toEqual(['down', 'up']);
    expect(results[1].latencyMs).toBeGreaterThanOrEqual(0);

    await createCheck(noc, { assetId: id, kind: 'icmp', target: '127.0.0.1', port: null });
    await scheduler.runDueChecks(new Date(Date.now() + 120_000));
    const all = await jsonOf(
      await h.app.request(`/api/v1/monitoring/checks?assetId=${id}`, { headers: authed(analyst) }),
    );
    const icmp = all.find((c: { kind: string }) => c.kind === 'icmp');
    const icmpResults = await jsonOf(
      await h.app.request(`/api/v1/monitoring/checks/${icmp.id}/results`, {
        headers: authed(analyst),
      }),
    );
    expect(icmpResults[0].outcome).toBe('unsupported');
    expect(
      (
        await h.app.request(`/api/v1/monitoring/checks/${check.id}/results`, {
          method: 'POST',
          headers: authed(noc),
          body: JSON.stringify([{ observedAt: new Date().toISOString(), outcome: 'up' }]),
        })
      ).status,
    ).toBe(409);
  });

  it('distinguishes device failure from loss of the monitoring path via collector heartbeat', async () => {
    const id = await createAsset('10.20.1.5');
    const sensor = await jsonOf(
      await h.app.request('/api/v1/sensors', {
        method: 'POST',
        headers: authed(admin.token),
        body: JSON.stringify({
          name: 'collector-a',
          kind: 'host_agent',
          site: 'hq',
          monitoredSegmentIds: [],
          engineVersion: null,
        }),
      }),
    );
    expect(sensor.mode).toBe('out_of_band');
    const check = await jsonOf(
      await createCheck(noc, {
        assetId: id,
        kind: 'tcp',
        target: '10.20.1.5',
        port: 443,
        collectorId: sensor.id,
      }),
    );

    // Collector never sent a heartbeat → its "down" is not trusted as device failure.
    const r1 = await jsonOf(
      await h.app.request(`/api/v1/monitoring/checks/${check.id}/results`, {
        method: 'POST',
        headers: authed(noc),
        body: JSON.stringify([{ observedAt: new Date().toISOString(), outcome: 'down' }]),
      }),
    );
    expect(r1.operationalStatus).toBe('unreachable_monitoring_path');
    expect(await assetStatus(id)).toBe('unreachable_monitoring_path');

    // Heartbeat arrives → collector healthy → the same evidence now means offline.
    const hb = await h.app.request(`/api/v1/sensors/${sensor.id}/heartbeat`, {
      method: 'POST',
      headers: authed(noc),
      body: JSON.stringify({ state: 'healthy', packetsCaptured: null, packetsDropped: null }),
    });
    expect(hb.status).toBe(202);
    expect((await jsonOf(hb)).derivedState).toBe('healthy');
    const r2 = await jsonOf(
      await h.app.request(`/api/v1/monitoring/checks/${check.id}/results`, {
        method: 'POST',
        headers: authed(noc),
        body: JSON.stringify([{ observedAt: new Date().toISOString(), outcome: 'down' }]),
      }),
    );
    expect(r2.operationalStatus).toBe('offline');
    const st = await jsonOf(
      await h.app.request(`/api/v1/sensors/${sensor.id}/status`, { headers: authed(analyst) }),
    );
    expect(st.latest.packetsDropped).toBeNull(); // not fabricated as zero
    expect(
      (
        await h.app.request('/api/v1/sensors', {
          method: 'POST',
          headers: authed(admin.token),
          body: JSON.stringify({
            name: 'x',
            kind: 'suricata',
            site: null,
            monitoredSegmentIds: [],
            engineVersion: null,
            mode: 'inline_prevention',
          }),
        })
      ).status,
    ).toBe(400);
  });

  it('maintenance windows override status and require exactly one scope', async () => {
    const id = await createAsset('127.0.0.1');
    const now = Date.now();
    const bad = await h.app.request('/api/v1/monitoring/maintenance-windows', {
      method: 'POST',
      headers: authed(noc),
      body: JSON.stringify({
        assetId: id,
        segmentId: id,
        startsAt: new Date(now).toISOString(),
        endsAt: new Date(now + 3600_000).toISOString(),
        reason: 'x',
      }),
    });
    expect(bad.status).toBe(400);
    const w = await h.app.request('/api/v1/monitoring/maintenance-windows', {
      method: 'POST',
      headers: authed(noc),
      body: JSON.stringify({
        assetId: id,
        segmentId: null,
        startsAt: new Date(now - 60_000).toISOString(),
        endsAt: new Date(now + 3600_000).toISOString(),
        reason: 'firmware upgrade',
      }),
    });
    expect(w.status).toBe(201);
    expect(await assetStatus(id)).toBe('maintenance');
    const ov = MonitoringOverview.parse(
      await jsonOf(
        await h.app.request('/api/v1/monitoring/overview', { headers: authed(analyst) }),
      ),
    );
    expect(ov.assetsByStatus.maintenance).toBe(1);
    expect(ov.activeMaintenanceWindows).toHaveLength(1);
  });

  it('stores and serves bounded metric ranges', async () => {
    const id = await createAsset('127.0.0.1');
    const pts = Array.from({ length: 3 }, (_, i) => ({
      metric: 'cpu.utilization',
      observedAt: new Date(Date.UTC(2026, 9, 18, 10, i)).toISOString(),
      value: 10 * i,
      unit: '%',
    }));
    expect(
      (
        await h.app.request(`/api/v1/assets/${id}/metrics`, {
          method: 'POST',
          headers: authed(analyst),
          body: JSON.stringify({ source: 'agent', points: pts }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await h.app.request(`/api/v1/assets/${id}/metrics`, {
          method: 'POST',
          headers: authed(noc),
          body: JSON.stringify({ source: 'agent', points: pts }),
        })
      ).status,
    ).toBe(202);
    const ok = await jsonOf(
      await h.app.request(
        `/api/v1/assets/${id}/metrics?metric=cpu.utilization&from=2026-10-18T09:00:00Z&to=2026-10-18T11:00:00Z`,
        { headers: authed(analyst) },
      ),
    );
    expect(ok.map((p: { value: number }) => p.value)).toEqual([0, 10, 20]);
    expect(
      (
        await h.app.request(
          `/api/v1/assets/${id}/metrics?metric=cpu.utilization&from=2026-10-01T00:00:00Z&to=2026-10-18T11:00:00Z`,
          { headers: authed(analyst) },
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await h.app.request(`/api/v1/assets/${id}/metrics`, {
          method: 'POST',
          headers: authed(noc),
          body: JSON.stringify({
            source: 'agent',
            points: [
              { metric: 'DROP TABLE', observedAt: pts[0]!.observedAt, value: 1, unit: null },
            ],
          }),
        })
      ).status,
    ).toBe(400);
  });
});
