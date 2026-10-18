import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
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
let analyst: string;
let noc: string;
let sensorId: string;
const PW = 'agents-password-that-is-long-enough';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, asset_services, asset_metrics, sensors, sensor_health cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  await createUser(h, admin.token, {
    email: 'noc@test.local',
    password: PW,
    roles: ['noc_operator'],
  });
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  noc = (await login(h, 'noc@test.local', PW)).body.accessToken;
  sensorId = (
    await jsonOf(
      await h.app.request('/api/v1/sensors', {
        method: 'POST',
        headers: authed(admin.token),
        body: JSON.stringify({
          name: 'agent-ws-01',
          kind: 'host_agent',
          site: 'hq',
          monitoredSegmentIds: [],
          engineVersion: null,
        }),
      }),
    )
  ).id;
});

const enrolToken = async () =>
  jsonOf(
    await h.app.request(`/api/v1/sensors/${sensorId}/enrolment-token`, {
      method: 'POST',
      headers: authed(admin.token),
    }),
  );
const enrol = (token: string) =>
  h.app.request('/api/v1/agents/enrol', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      enrolmentToken: token,
      hostname: 'ws-01',
      platform: { os: 'Ubuntu', osVersion: '24.04', kernel: '6.8', arch: 'x86_64' },
      agentVersion: '0.1.0',
    }),
  });
const asAgent = (credential: string) => ({
  'content-type': 'application/json',
  'x-sensor-credential': credential,
});
const inventory = (over: Record<string, unknown> = {}) => ({
  observedAt: '2026-10-18T12:00:00Z',
  hostname: 'ws-01',
  platform: { os: 'Ubuntu', osVersion: '24.04', kernel: '6.8.0', arch: 'x86_64' },
  hardware: {
    manufacturer: 'Dell',
    model: 'Latitude 5540',
    cpuModel: 'i7',
    cpuCores: 8,
    ramMb: 16384,
    disks: [{ device: 'nvme0n1', sizeGb: 512, fsType: 'ext4', mountPoint: '/' }],
    serialNumber: null,
  },
  interfaces: [
    { name: 'lo', macAddress: null, addresses: ['127.0.0.1'], operState: 'up' },
    {
      name: 'eth0',
      macAddress: 'aa:bb:cc:dd:ee:01',
      addresses: ['10.20.5.9'],
      operState: 'up',
      speedMbps: 1000,
    },
  ],
  listeningServices: [
    { proto: 'tcp', port: 22, address: null, process: 'sshd' },
    { proto: 'tcp', port: 9100, address: '127.0.0.1', process: 'node_exporter' },
  ],
  bootTime: '2026-10-17T08:00:00Z',
  agentVersion: '0.1.0',
  ...over,
});

async function enrolled(): Promise<string> {
  const { token } = await enrolToken();
  const r = await enrol(token);
  expect(r.status).toBe(201);
  return (await jsonOf(r)).credential as string;
}

describe('host agent foundation', () => {
  it('enrolment tokens need sensors.manage, are single-use, and bad tokens are refused', async () => {
    expect(
      (
        await h.app.request(`/api/v1/sensors/${sensorId}/enrolment-token`, {
          method: 'POST',
          headers: authed(noc),
        })
      ).status,
    ).toBe(403);
    const { token, expiresAt } = await enrolToken();
    expect(token.length).toBeGreaterThanOrEqual(32);
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());
    expect((await enrol('definitely-not-a-valid-enrolment-token-value')).status).toBe(401);
    const ok = await enrol(token);
    expect(ok.status).toBe(201);
    const body = await jsonOf(ok);
    expect(body.credential.startsWith(`${sensorId}.`)).toBe(true);
    expect((await enrol(token)).status).toBe(401); // burned
    const audits = (await h.handle.db.execute(
      sql`select outcome from audit_events where action = 'agents.enrol' order by seq`,
    )) as unknown as Array<{ outcome: string }>;
    expect(audits.map((a) => a.outcome)).toEqual(['denied', 'success', 'denied']);
  });

  it('sensor credentials and user tokens are not interchangeable', async () => {
    const cred = await enrolled();
    expect(
      (
        await h.app.request('/api/v1/agents/heartbeat', {
          method: 'POST',
          headers: authed(admin.token),
          body: JSON.stringify({ state: 'healthy' }),
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await h.app.request('/api/v1/agents/heartbeat', {
          method: 'POST',
          headers: asAgent('wrong.credential'),
          body: JSON.stringify({ state: 'healthy' }),
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await h.app.request('/api/v1/agents/heartbeat', {
          method: 'POST',
          headers: asAgent(cred),
          body: JSON.stringify({ state: 'healthy' }),
        })
      ).status,
    ).toBe(204);
    expect((await h.app.request('/api/v1/assets', { headers: asAgent(cred) })).status).toBe(401);
    expect((await h.app.request('/api/v1/auth/me', { headers: asAgent(cred) })).status).toBe(401);
    const st = await jsonOf(
      await h.app.request(`/api/v1/sensors/${sensorId}/status`, { headers: authed(analyst) }),
    );
    expect(st.derivedState).toBe('healthy');
  });

  it('inventory creates the host asset with interfaces and services, then updates it on re-send', async () => {
    const cred = await enrolled();
    const r = await h.app.request('/api/v1/agents/inventory', {
      method: 'POST',
      headers: asAgent(cred),
      body: JSON.stringify(inventory()),
    });
    if (r.status !== 202) throw new Error(`inventory failed: ${await r.clone().text()}`);
    expect(r.status).toBe(202);
    const body = await jsonOf(r);
    expect(body.decision).toBe('create');
    const detail = await jsonOf(
      await h.app.request(`/api/v1/assets/${body.assetId}`, { headers: authed(analyst) }),
    );
    expect(detail.asset).toMatchObject({
      hostname: 'ws-01',
      osName: 'Ubuntu',
      osVersion: '24.04',
      cpuArchitecture: 'x86_64',
      ramMb: 16384,
      manufacturer: 'Dell',
      model: 'Latitude 5540',
      monitoringCoverage: 'partial',
      discoveryMethods: ['endpoint_agent'],
    });
    expect(detail.asset.ipAddresses).toEqual(['10.20.5.9']); // loopback excluded
    expect(detail.interfaces.map((i: { name: string }) => i.name)).toEqual(['eth0']);
    expect(
      detail.services.map((s: { port: number; process: string }) => [s.port, s.process]),
    ).toEqual([
      [22, 'sshd'],
      [9100, 'node_exporter'],
    ]);
    // Re-send with a changed IP and one service gone: same asset (agent id), services replaced, first-seen kept.
    const again = await jsonOf(
      await h.app.request('/api/v1/agents/inventory', {
        method: 'POST',
        headers: asAgent(cred),
        body: JSON.stringify(
          inventory({
            observedAt: '2026-10-18T13:00:00Z',
            interfaces: [
              {
                name: 'eth0',
                macAddress: 'aa:bb:cc:dd:ee:01',
                addresses: ['10.20.5.77'],
                operState: 'up',
              },
            ],
            listeningServices: [{ proto: 'tcp', port: 22, address: null, process: 'sshd' }],
          }),
        ),
      }),
    );
    expect(again.decision).toBe('match');
    expect(again.assetId).toBe(body.assetId);
    const d2 = await jsonOf(
      await h.app.request(`/api/v1/assets/${body.assetId}`, { headers: authed(analyst) }),
    );
    expect(d2.services).toHaveLength(1);
    expect(d2.services[0].firstSeenAt).toBe('2026-10-18T12:00:00.000Z');
    expect(d2.services[0].lastSeenAt).toBe('2026-10-18T13:00:00.000Z');
    expect(
      (await jsonOf(await h.app.request('/api/v1/assets', { headers: authed(analyst) }))).items,
    ).toHaveLength(1);
    const sensor = await jsonOf(
      await h.app.request(`/api/v1/sensors/${sensorId}/status`, { headers: authed(analyst) }),
    );
    expect(sensor.sensor.hostAssetId).toBe(body.assetId);
  });

  it('agent metrics require an inventory first and land on the host asset', async () => {
    const cred = await enrolled();
    const pts = {
      source: 'agent',
      points: [
        { metric: 'cpu.utilization', observedAt: '2026-10-18T12:00:00Z', value: 42, unit: '%' },
      ],
    };
    expect(
      (
        await h.app.request('/api/v1/agents/metrics', {
          method: 'POST',
          headers: asAgent(cred),
          body: JSON.stringify(pts),
        })
      ).status,
    ).toBe(409);
    const inv = await jsonOf(
      await h.app.request('/api/v1/agents/inventory', {
        method: 'POST',
        headers: asAgent(cred),
        body: JSON.stringify(inventory()),
      }),
    );
    expect(
      (
        await h.app.request('/api/v1/agents/metrics', {
          method: 'POST',
          headers: asAgent(cred),
          body: JSON.stringify(pts),
        })
      ).status,
    ).toBe(202);
    const m = await jsonOf(
      await h.app.request(
        `/api/v1/assets/${inv.assetId}/metrics?metric=cpu.utilization&from=2026-10-18T00:00:00Z&to=2026-10-19T00:00:00Z`,
        { headers: authed(analyst) },
      ),
    );
    expect(m).toHaveLength(1);
  });

  it('passive neighbour batches create observations without merging on IP alone', async () => {
    const cred = await enrolled();
    const batch = {
      entries: [
        {
          ip: '10.20.5.1',
          mac: 'aa:bb:cc:dd:ee:f1',
          source: 'arp',
          observedAt: '2026-10-18T12:00:00Z',
          interface: 'eth0',
        },
        {
          ip: '10.20.5.1',
          mac: 'aa:bb:cc:dd:ee:f1',
          source: 'arp',
          observedAt: '2026-10-18T12:01:00Z',
          interface: 'eth0',
        },
        {
          ip: '10.20.5.50',
          mac: 'aa:bb:cc:dd:ee:50',
          source: 'dhcp',
          hostname: 'printer-lobby',
          observedAt: '2026-10-18T12:00:00Z',
        },
        { ip: '10.20.5.99', mac: null, source: 'arp', observedAt: '2026-10-18T12:00:00Z' },
        {
          ip: '127.0.0.1',
          mac: 'aa:bb:cc:dd:ee:ff',
          source: 'arp',
          observedAt: '2026-10-18T12:00:00Z',
        },
      ],
    };
    const r = await h.app.request('/api/v1/agents/neighbors', {
      method: 'POST',
      headers: asAgent(cred),
      body: JSON.stringify(batch),
    });
    expect(r.status).toBe(202);
    expect(await jsonOf(r)).toEqual({
      received: 5,
      created: 2,
      matched: 1,
      ambiguous: 0,
      skipped: 2,
    });
    const list = await jsonOf(await h.app.request('/api/v1/assets', { headers: authed(analyst) }));
    expect(
      list.items
        .map((a: { hostname: string | null; discoveryMethods: string[] }) => [
          a.hostname,
          a.discoveryMethods,
        ])
        .sort(),
    ).toEqual([
      [null, ['arp_neighbor']],
      ['printer-lobby', ['dhcp_lease']],
    ]);
    // Collectors (users with monitoring.ingest) may push the same batch shape.
    expect(
      (
        await h.app.request('/api/v1/collectors/neighbors', {
          method: 'POST',
          headers: authed(analyst),
          body: JSON.stringify(batch),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await h.app.request('/api/v1/collectors/neighbors', {
          method: 'POST',
          headers: authed(noc),
          body: JSON.stringify(batch),
        })
      ).status,
    ).toBe(202);
  });
});
