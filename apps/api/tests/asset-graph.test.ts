import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { AssetGraph, AssetRiskProfile } from '@noc/shared';
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
let noc: string; // noc_operator: observations, segments, sites
let analyst: string; // soc_analyst: assets.read, alerts.read, findings.read
let blue: string; // blue_team_engineer: events.ingest, detection_rules.change
let red: string; // red_team_operator: assets.read + findings.read, no alerts.read
const PW = 'asset-graph-password-long-enough';

const post = (path: string, token: string, body: unknown) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });
const observe = (ip: string, mac: string, host: string) =>
  post('/api/v1/assets/observations', noc, {
    source: 'test',
    method: 'passive_observation',
    observedAt: new Date().toISOString(),
    identifiers: { macAddresses: [mac], ipAddresses: [ip], hostnames: [host] },
    attributes: {},
  });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, asset_services, network_segments, security_events, sensors, topology_relationships, detection_rules cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['noc@test.local', 'noc_operator'],
    ['analyst@test.local', 'soc_analyst'],
    ['blue@test.local', 'blue_team_engineer'],
    ['red@test.local', 'red_team_operator'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [noc, analyst, blue, red] = (await Promise.all(
    ['noc', 'analyst', 'blue', 'red'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string, string];
});

describe('asset dependency graph and risk profile', () => {
  it('draws edges only from recorded topology and observed traffic, and explains each asset risk with its sources', async () => {
    expect((await post('/api/v1/sites', noc, { key: 'dc1', name: 'DC 1' })).status).toBe(201);
    await post('/api/v1/network/segments', noc, {
      name: 'dc1-servers',
      site: 'dc1',
      cidr: '10.1.0.0/24',
      vlanId: null,
      activeDiscoveryAllowed: false,
      description: null,
    });
    const web = (await jsonOf(await observe('10.1.0.10', 'aa:aa:aa:aa:aa:01', 'web-01')))
      .assetId as string;
    const db = (await jsonOf(await observe('10.1.0.20', 'aa:aa:aa:aa:aa:02', 'db-01')))
      .assetId as string;
    const lone = (await jsonOf(await observe('10.1.0.30', 'aa:aa:aa:aa:aa:03', 'lone-01')))
      .assetId as string;
    // Recorded topology: web-01 → db-01 (service dependency) ; open ports on db-01 ; a finding on db-01.
    await h.handle.db.execute(
      sql`insert into topology_relationships (kind, source_asset_id, target_asset_id, verification, evidence) values ('service_dependency', ${web}::uuid, ${db}::uuid, 'verified', 'app config references db-01:5432')`,
    );
    await h.handle.db.execute(
      sql`insert into asset_services (asset_id, proto, port, source) values (${db}::uuid, 'tcp', 5432, 'agent'), (${db}::uuid, 'tcp', 445, 'agent'), (${web}::uuid, 'tcp', 443, 'agent')`,
    );
    await h.handle.db.execute(
      sql`insert into vulnerability_findings (asset_id, title, severity, description, cve, validated) values (${db}::uuid, 'PostgreSQL exposed to the server VLAN', 'high', 'test', ARRAY['CVE-2024-0001']::text[], true)`,
    );
    // Observed traffic: a sensor sees two events web-01 → db-01 and one db-01 → web-01, carrying a rule with an ATT&CK technique.
    const sensor = await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name: 'ids-dc1',
        kind: 'suricata',
        site: 'dc1',
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    );
    await post('/api/v1/detection-rules/import', blue, {
      source: 'et_open',
      ruleSet: 'scan',
      license: 'BSD-2-Clause',
      content:
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"ET SCAN Potential DB Scan"; classtype:attempted-recon; sid:2001219; rev:20; metadata:mitre_technique_id T1046, signature_severity Minor;)\n',
    });
    const eve = (fid: number, src: string, dst: string, port: number) =>
      JSON.stringify({
        timestamp: new Date().toISOString().replace('Z', '+0000'),
        flow_id: fid,
        event_type: 'alert',
        src_ip: src,
        src_port: 40000 + fid,
        dest_ip: dst,
        dest_port: port,
        proto: 'TCP',
        alert: {
          action: 'allowed',
          gid: 1,
          signature_id: 2001219,
          rev: 20,
          signature: 'ET SCAN Potential DB Scan',
          category: 'Attempted Information Leak',
          severity: 2,
        },
      });
    const ing = await h.app.request(`/api/v1/ingest/suricata/eve?sensorId=${sensor.id}`, {
      method: 'POST',
      headers: { ...authed(blue), 'content-type': 'application/x-ndjson' },
      body: [
        eve(1, '10.1.0.10', '10.1.0.20', 5432),
        eve(2, '10.1.0.10', '10.1.0.20', 5432),
        eve(3, '10.1.0.20', '10.1.0.10', 443),
      ].join('\n'),
    });
    expect(ing.status).toBe(202);

    // Graph: three nodes, one topology edge, two traffic edges (direction preserved), lone-01 isolated.
    const g = AssetGraph.parse(await jsonOf(await get('/api/v1/assets/graph?hours=24', analyst)));
    expect(g.nodes.map((n) => n.label).sort()).toEqual(['db-01', 'lone-01', 'web-01']);
    expect(g.nodes.find((n) => n.id === db)).toMatchObject({
      site: 'dc1',
      openFindings: 1,
      openPorts: 2,
    });
    const topo = g.edges.filter((e) => e.basis === 'topology');
    expect(topo).toHaveLength(1);
    expect(topo[0]).toMatchObject({
      sourceAssetId: web,
      targetAssetId: db,
      kind: 'service_dependency',
      verification: 'verified',
    });
    const traffic = g.edges.filter((e) => e.basis === 'observed_traffic');
    expect(traffic.map((e) => [e.sourceAssetId, e.targetAssetId, e.weight, e.ports])).toEqual(
      expect.arrayContaining([
        [web, db, 2, [5432]],
        [db, web, 1, [443]],
      ]),
    );
    expect(g.edges.some((e) => e.sourceAssetId === lone || e.targetAssetId === lone)).toBe(false);
    expect(g.truncated).toBe(false);
    const dbNode = g.nodes.find((n) => n.id === db)!;
    expect(['high', 'critical']).toContain(dbNode.risk.level);
    // lone-01: unmonitored, no evidence → unknown, not safe.
    expect(g.nodes.find((n) => n.id === lone)!.risk.level).toBe('unknown');

    // Risk profile for db-01: ports with source, exposure techniques, alert techniques, finding with CVE, neighbours.
    const p = AssetRiskProfile.parse(await jsonOf(await get(`/api/v1/assets/${db}/risk`, analyst)));
    expect(p.asset.hostname).toBe('db-01');
    expect(p.openPorts.map((o) => [o.port, o.service, o.source])).toEqual([
      [445, 'SMB', 'inventory:agent'],
      [5432, 'PostgreSQL', 'inventory:agent'],
    ]);
    expect(p.techniques.find((t) => t.techniqueId === 'T1046')).toMatchObject({
      name: 'Network Service Discovery',
      tactic: 'discovery',
      source: 'alert',
    });
    expect(p.techniques.find((t) => t.techniqueId === 'T1021.002')).toMatchObject({
      source: 'exposure',
      name: 'SMB/Windows Admin Shares',
    });
    expect(
      p.techniques.find((t) => t.techniqueId === 'T1213' && t.source === 'exposure'),
    ).toBeTruthy();
    expect(p.findingsIncluded).toBe(true);
    expect(p.findings[0]).toMatchObject({
      title: 'PostgreSQL exposed to the server VLAN',
      cve: ['CVE-2024-0001'],
    });
    expect(p.alertsIncluded).toBe(true);
    expect(p.alerts.length).toBeGreaterThan(0);
    expect(p.alerts[0]!.techniques).toEqual(['T1046']);
    expect(p.neighbors.map((n) => [n.label, n.basis, n.direction]).sort()).toEqual([
      ['web-01', 'observed_traffic', 'both'],
      ['web-01', 'topology', 'in'],
    ]);
    expect(p.risk.basis.join(' ')).toMatch(/1 open finding\(s\), highest high/);
    expect(p.risk.basis.join(' ')).toMatch(/risky services \(445, 5432\)/);
    // Observation-reported ports (assessment/discovery) are included with their source.
    await post('/api/v1/assets/observations', noc, {
      source: 'assessment:test',
      method: 'tcp_service_check',
      observedAt: new Date().toISOString(),
      identifiers: { macAddresses: [], ipAddresses: ['10.1.0.30'], hostnames: [] },
      attributes: { openPorts: '22,3389' },
    });
    const lp = AssetRiskProfile.parse(
      await jsonOf(await get(`/api/v1/assets/${lone}/risk`, analyst)),
    );
    expect(lp.openPorts.map((o) => [o.port, o.source])).toEqual([
      [22, 'observation:assessment:test'],
      [3389, 'observation:assessment:test'],
    ]);
    expect(
      lp.techniques.some((t) => t.techniqueId === 'T1021.001' && t.source === 'exposure'),
    ).toBe(true);
    expect(lp.risk.level).not.toBe('unknown'); // exposure is evidence

    // Permission gating: a red-team operator (no alerts.read) gets the profile with alerts withheld.
    const ap = AssetRiskProfile.parse(await jsonOf(await get(`/api/v1/assets/${db}/risk`, red)));
    expect(ap.alertsIncluded).toBe(false);
    expect(ap.alerts).toEqual([]);
    expect(ap.findingsIncluded).toBe(true); // red_team_operator holds findings.read
    expect(ap.risk.basis.join(' ')).toMatch(/alerts not visible/);
    expect(
      (await get('/api/v1/assets/00000000-0000-4000-8000-00000000dead/risk', analyst)).status,
    ).toBe(404);
    expect((await get('/api/v1/assets/graph', blue)).status).toBe(200);
  });
});
