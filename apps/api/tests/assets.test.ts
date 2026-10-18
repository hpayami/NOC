import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Asset, AssetCoverageSummary } from '@noc/shared';
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
let collector: string; // noc_operator token (holds discovery.run_passive)
let analyst: string; // soc_analyst token (assets.read only)
let secadmin: string; // security_admin token (assets.read_sensitive)
const PW = 'collector-password-that-is-long';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    (await import('drizzle-orm'))
      .sql`truncate table asset_observations, asset_interfaces, network_segments, topology_relationships cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'collector@test.local',
    password: PW,
    roles: ['noc_operator'],
  });
  await createUser(h, admin.token, {
    email: 'analyst@test.local',
    password: PW,
    roles: ['soc_analyst'],
  });
  collector = (await login(h, 'collector@test.local', PW)).body.accessToken;
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  await createUser(h, admin.token, {
    email: 'secadmin@test.local',
    password: PW,
    roles: ['security_admin'],
  });
  secadmin = (await login(h, 'secadmin@test.local', PW)).body.accessToken;
});

const obs = (over: Record<string, unknown> = {}, ids: Record<string, unknown> = {}) => ({
  source: 'test-collector',
  method: 'arp_neighbor',
  observedAt: '2026-10-18T10:00:00Z',
  identifiers: {
    macAddresses: ['aa:bb:cc:dd:ee:01'],
    ipAddresses: ['10.20.5.9'],
    hostnames: ['ws-01'],
    ...ids,
  },
  attributes: {},
  ...over,
});
const post = (token: string, body: unknown) =>
  h.app.request('/api/v1/assets/observations', {
    method: 'POST',
    headers: authed(token),
    body: JSON.stringify(body),
  });
const list = async (token: string, qs = '') =>
  jsonOf(await h.app.request(`/api/v1/assets${qs}`, { headers: authed(token) }));

describe('observation ingestion and identity resolution', () => {
  it('requires discovery.run_passive', async () => {
    expect((await post(analyst, obs())).status).toBe(403);
    expect(
      (
        await h.app.request('/api/v1/assets/observations', {
          method: 'POST',
          body: JSON.stringify(obs()),
        })
      ).status,
    ).toBe(401);
  });

  it('creates an asset from a first observation and exposes it (unmonitored, not "secure")', async () => {
    const r = await post(
      collector,
      obs({ attributes: { osName: 'Ubuntu', ramMb: 8192, serialNumber: 'SN-1' } }),
    );
    expect(r.status).toBe(201);
    const body = await jsonOf(r);
    expect(body.decision).toBe('create');
    const page = await list(analyst);
    expect(page.items).toHaveLength(1);
    const a = Asset.parse(page.items[0]);
    expect(a.hostname).toBe('ws-01');
    expect(a.ipAddresses).toEqual(['10.20.5.9']);
    expect(a.osName).toBe('Ubuntu');
    expect(a.ramMb).toBe(8192);
    expect(a.monitoringCoverage).toBe('unmonitored');
    expect(a.assuranceState).toBe('asset_not_monitored');
    expect(a.serialNumber).toBeNull(); // analyst lacks assets.read_sensitive
    expect((await list(admin.token)).items[0].serialNumber).toBeNull(); // platform_admin: no read_sensitive either
    expect((await list(secadmin)).items[0].serialNumber).toBe('SN-1'); // security_admin holds assets.read_sensitive
  });

  it('correlates a second observation by MAC despite a new IP and keeps one asset', async () => {
    await post(collector, obs());
    const r = await jsonOf(
      await post(
        collector,
        obs({ observedAt: '2026-10-18T11:00:00Z' }, { ipAddresses: ['10.20.5.77'], hostnames: [] }),
      ),
    );
    expect(r.decision).toBe('match');
    expect(r.reason).toBe('mac_overlap');
    const page = await list(analyst);
    expect(page.items).toHaveLength(1);
    expect(page.items[0].ipAddresses.sort()).toEqual(['10.20.5.77', '10.20.5.9']);
    expect(page.items[0].lastSeenAt).toBe('2026-10-18T11:00:00.000Z');
    const detail = await jsonOf(
      await h.app.request(`/api/v1/assets/${page.items[0].id}`, { headers: authed(analyst) }),
    );
    expect(detail.interfaces).toHaveLength(1);
  });

  it('never merges two devices that only share an IP address', async () => {
    await post(collector, obs());
    const r = await jsonOf(
      await post(collector, obs({}, { macAddresses: ['aa:bb:cc:dd:ee:02'], hostnames: ['other'] })),
    );
    expect(r.decision).toBe('create');
    expect((await list(analyst)).items).toHaveLength(2);
  });

  it('re-attaches address-only observations (scan hits) to the sole holder of the address', async () => {
    const first = await jsonOf(await post(collector, obs()));
    const probe = (ip: string) =>
      post(collector, {
        source: 'discovery:test',
        method: 'tcp_service_check',
        observedAt: '2026-10-18T11:00:00Z',
        identifiers: { macAddresses: [], ipAddresses: [ip], hostnames: [] },
        attributes: { openPorts: '22' },
      });
    const r = await jsonOf(await probe('10.20.5.9'));
    expect(r.decision).toBe('match');
    expect(r.assetId).toBe(first.assetId);
    expect((await list(analyst)).items).toHaveLength(1);
    // An address nobody holds still creates (a reachable host is an asset, however thin).
    expect((await jsonOf(await probe('10.20.5.250'))).decision).toBe('create');
    expect((await list(analyst)).items).toHaveLength(2);
  });

  it('prefers the agent id and records a MAC conflict', async () => {
    await post(collector, obs({}, { agentId: 'agent-7', macAddresses: ['11:22:33:44:55:66'] }));
    const r = await jsonOf(
      await post(
        collector,
        obs({}, { agentId: 'agent-7', macAddresses: ['aa:bb:cc:dd:ee:09'], hostnames: [] }),
      ),
    );
    expect(r.decision).toBe('match');
    expect(r.reason).toBe('agent_id');
    expect(r.conflicts).toContain('mac_set_disjoint');
    expect((await list(analyst)).items).toHaveLength(1);
  });

  it('leaves ambiguous observations unlinked and visible as unresolved', async () => {
    await post(collector, obs({}, { macAddresses: ['aa:bb:cc:dd:ee:01'], hostnames: ['a'] }));
    await post(collector, obs({}, { macAddresses: ['aa:bb:cc:dd:ee:02'], hostnames: ['b'] }));
    const r = await jsonOf(
      await post(
        collector,
        obs({}, { macAddresses: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'], hostnames: [] }),
      ),
    );
    expect(r.decision).toBe('ambiguous');
    expect(r.candidateIds).toHaveLength(2);
    expect(r.assetId).toBeNull();
    const cov = AssetCoverageSummary.parse(
      await jsonOf(await h.app.request('/api/v1/assets/coverage', { headers: authed(analyst) })),
    );
    expect(cov.total).toBe(2);
    expect(cov.unresolvedObservations).toBe(1);
    expect(cov.byCoverage.unmonitored).toBe(2);
    expect(cov.byAssurance.asset_not_monitored).toBe(2);
  });

  it('infers the segment from configured CIDRs and lets hostname match inside it only', async () => {
    const seg = await jsonOf(
      await h.app.request('/api/v1/network/segments', {
        method: 'POST',
        headers: authed(admin.token),
        body: JSON.stringify({
          name: 'office',
          site: 'hq',
          cidr: '10.20.0.0/16',
          vlanId: 20,
          activeDiscoveryAllowed: false,
          description: null,
        }),
      }),
    );
    expect(seg.id).toBeTruthy();
    await post(
      collector,
      obs({}, { macAddresses: [], hostnames: ['printer-1'], ipAddresses: ['10.20.9.9'] }),
    );
    const same = await jsonOf(
      await post(
        collector,
        obs({}, { macAddresses: [], hostnames: ['printer-1'], ipAddresses: ['10.20.9.10'] }),
      ),
    );
    expect(same.decision).toBe('match');
    expect(same.reason).toBe('hostname_segment');
    const other = await jsonOf(
      await post(
        collector,
        obs({}, { macAddresses: [], hostnames: ['printer-1'], ipAddresses: ['192.168.1.5'] }),
      ),
    );
    expect(other.decision).toBe('create');
    const page = await list(analyst, `?segmentId=${seg.id}`);
    expect(page.items).toHaveLength(1);
    expect(page.items[0].segmentId).toBe(seg.id);
  });

  it('paginates with a keyset cursor and filters by class/query', async () => {
    for (let i = 0; i < 5; i++)
      await post(
        collector,
        obs(
          { observedAt: `2026-10-18T10:0${i}:00Z` },
          { macAddresses: [`aa:bb:cc:dd:ee:1${i}`], hostnames: [`host-${i}`] },
        ),
      );
    const p1 = await list(analyst, '?limit=2');
    expect(p1.items).toHaveLength(2);
    expect(p1.nextCursor).toBeTruthy();
    const p2 = await list(analyst, `?limit=2&cursor=${p1.nextCursor}`);
    if (!p2.items) throw new Error(`page 2 failed: ${JSON.stringify(p2)}`);
    expect(p2.items[0].id).not.toBe(p1.items[0].id);
    expect(p2.items[0].lastSeenAt <= p1.items[1].lastSeenAt).toBe(true);
    expect((await list(analyst, '?q=host-3')).items).toHaveLength(1);
    expect((await list(analyst, '?assetClass=firewall')).items).toHaveLength(0);
    expect(
      (await h.app.request('/api/v1/assets?cursor=garbage', { headers: authed(analyst) })).status,
    ).toBe(400);
  });

  it('metadata patch needs assets.manage, never touches identity, and is audited', async () => {
    await post(collector, obs());
    const id = (await list(analyst)).items[0].id;
    expect(
      (
        await h.app.request(`/api/v1/assets/${id}`, {
          method: 'PATCH',
          headers: authed(analyst),
          body: JSON.stringify({ criticality: 'high' }),
        })
      ).status,
    ).toBe(403);
    const ok = await h.app.request(`/api/v1/assets/${id}`, {
      method: 'PATCH',
      headers: authed(collector),
      body: JSON.stringify({ criticality: 'high', assetClass: 'workstation' }),
    });
    expect(ok.status).toBe(200);
    expect((await jsonOf(ok)).criticality).toBe('high');
    expect(
      (
        await h.app.request(`/api/v1/assets/${id}`, {
          method: 'PATCH',
          headers: authed(collector),
          body: JSON.stringify({ hostname: 'x' }),
        })
      ).status,
    ).toBe(400);
    const timeline = await jsonOf(
      await h.app.request(`/api/v1/assets/${id}/timeline`, { headers: authed(analyst) }),
    );
    expect(timeline.map((e: { kind: string }) => e.kind)).toEqual(
      expect.arrayContaining(['observation', 'audit']),
    );
  });

  it('topology reports nodes and no fabricated edges', async () => {
    await post(collector, obs());
    const g = await jsonOf(
      await h.app.request('/api/v1/network/topology', { headers: authed(analyst) }),
    );
    expect(g.nodes).toHaveLength(1);
    expect(g.edges).toEqual([]);
    expect(g.truncated).toBe(false);
  });
});
