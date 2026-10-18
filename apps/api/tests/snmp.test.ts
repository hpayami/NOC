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
let noc: string;
let analyst: string;
let collectorId: string;
const PW = 'snmp-password-that-is-long-enough';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, asset_metrics, topology_relationships, sensors, sensor_health cascade`,
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
  const sensor = await jsonOf(
    await h.app.request('/api/v1/sensors', {
      method: 'POST',
      headers: authed(admin.token),
      body: JSON.stringify({
        name: 'snmp-poller-hq',
        kind: 'snmp_poller',
        site: 'hq',
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    }),
  );
  collectorId = sensor.id;
});

const iface = (
  ifIndex: number,
  ifName: string,
  mac: string,
  over: Record<string, unknown> = {},
) => ({
  ifIndex,
  ifName,
  ifDescr: `${ifName} description`,
  ifSpeedBps: 1_000_000_000,
  ifPhysAddress: mac,
  ifAdminStatus: 'up',
  ifOperStatus: 'up',
  ifHCInOctets: 123456,
  ifHCOutOctets: 654321,
  ifInErrors: 0,
  addresses: [],
  ...over,
});
const snapshot = (over: Record<string, unknown> = {}) => ({
  collectorId,
  observedAt: '2026-10-18T12:00:00Z',
  agentAddress: '10.20.0.2',
  system: {
    sysName: 'core-sw-01',
    sysDescr: 'Example Switch OS 9.1',
    sysObjectId: '1.3.6.1.4.1.9.1.1',
    sysUpTimeSeconds: 86400,
  },
  interfaces: [
    iface(1, 'Gi1/0/1', 'aa:bb:cc:00:00:01', { addresses: ['10.20.0.2'] }),
    iface(2, 'Gi1/0/2', 'aa:bb:cc:00:00:02', { ifOperStatus: 'down' }),
  ],
  lldpNeighbors: [],
  ...over,
});
const post = (token: string, body: unknown) =>
  h.app.request('/api/v1/collectors/snmp/snapshots', {
    method: 'POST',
    headers: authed(token),
    body: JSON.stringify(body),
  });

describe('SNMPv3 snapshot ingestion', () => {
  it('requires monitoring.ingest and a known enabled collector', async () => {
    expect((await post(analyst, snapshot())).status).toBe(403);
    expect(
      (await post(noc, snapshot({ collectorId: '3f0c9a52-7f0e-4b0a-9a4c-0d2a2b6f6a11' }))).status,
    ).toBe(404);
    expect((await post(noc, snapshot({ interfaces: [iface(1, 'x', 'not-a-mac')] }))).status).toBe(
      400,
    );
  });

  it('creates the asset with per-interface detail and stores counters as metrics', async () => {
    const r = await post(noc, snapshot());
    expect(r.status).toBe(202);
    const body = await jsonOf(r);
    expect(body.decision).toBe('create');
    expect(body.interfacesUpserted).toBe(2);
    expect(body.metricsStored).toBeGreaterThanOrEqual(1 + 2 * 4);
    const detail = await jsonOf(
      await h.app.request(`/api/v1/assets/${body.assetId}`, { headers: authed(analyst) }),
    );
    expect(detail.asset.hostname).toBe('core-sw-01');
    expect(detail.asset.discoveryMethods).toEqual(['snmpv3']);
    expect(
      detail.interfaces.map((i: { name: string; operState: string; speedMbps: number }) => [
        i.name,
        i.operState,
        i.speedMbps,
      ]),
    ).toEqual([
      ['Gi1/0/1', 'up', 1000],
      ['Gi1/0/2', 'down', 1000],
    ]);
    const m = await jsonOf(
      await h.app.request(
        `/api/v1/assets/${body.assetId}/metrics?metric=if.1.in_octets&from=2026-10-18T00:00:00Z&to=2026-10-19T00:00:00Z`,
        { headers: authed(analyst) },
      ),
    );
    expect(m).toEqual([
      {
        metric: 'if.1.in_octets',
        observedAt: '2026-10-18T12:00:00.000Z',
        value: 123456,
        unit: 'B',
      },
    ]);
    // A second snapshot correlates by MAC and updates, not duplicates, the interfaces.
    const again = await jsonOf(
      await post(
        noc,
        snapshot({
          observedAt: '2026-10-18T12:05:00Z',
          interfaces: [iface(1, 'Gi1/0/1', 'aa:bb:cc:00:00:01', { ifOperStatus: 'down' })],
        }),
      ),
    );
    expect(again.decision).toBe('match');
    const detail2 = await jsonOf(
      await h.app.request(`/api/v1/assets/${body.assetId}`, { headers: authed(analyst) }),
    );
    expect(detail2.interfaces).toHaveLength(2);
    expect(detail2.interfaces.find((i: { name: string }) => i.name === 'Gi1/0/1').operState).toBe(
      'down',
    );
  });

  it('turns LLDP neighbours into verified edges only when the neighbour is a known asset', async () => {
    const a = await jsonOf(await post(noc, snapshot()));
    const b = await jsonOf(
      await post(
        noc,
        snapshot({
          agentAddress: '10.20.0.3',
          system: {
            sysName: 'access-sw-07',
            sysDescr: 'Example Switch OS 9.1',
            sysObjectId: '1.3.6.1.4.1.9.1.2',
            sysUpTimeSeconds: 100,
          },
          interfaces: [iface(1, 'Gi1/0/48', 'aa:bb:cc:00:07:48', { addresses: ['10.20.0.3'] })],
          lldpNeighbors: [
            {
              localIfIndex: 1,
              remoteChassisIdSubtype: 4,
              remoteChassisId: 'AA:BB:CC:00:00:01',
              remotePortId: 'Gi1/0/2',
              remoteSysName: 'core-sw-01',
            },
            {
              localIfIndex: 1,
              remoteChassisIdSubtype: 4,
              remoteChassisId: 'de:ad:be:ef:00:01',
              remotePortId: null,
              remoteSysName: 'unknown-device',
            },
          ],
        }),
      ),
    );
    expect(b.lldp).toEqual({ resolved: 1, unresolved: 1 });
    const g = await jsonOf(
      await h.app.request('/api/v1/network/topology', { headers: authed(analyst) }),
    );
    expect(g.nodes).toHaveLength(2);
    expect(g.edges).toHaveLength(1);
    expect(g.edges[0]).toMatchObject({
      kind: 'layer2_adjacency',
      verification: 'verified',
      sourceAssetId: b.assetId,
      targetAssetId: a.assetId,
    });
    expect(g.edges[0].evidence).toMatch(/LLDP-MIB/);
    expect(g.edges[0].sourceInterfaceId).toBeTruthy();
  });
});
