import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { AssetRiskProfile, FindingRecord, PlatformStatus, VulnerabilityRecord } from '@noc/shared';
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
let noc: string; // noc_operator: observations
let blue: string; // blue_team_engineer: threat_intel.manage
let analyst: string; // soc_analyst: findings.read, no threat_intel.manage
const PW = 'vulnerability-password-long-enough';

const post = (path: string, token: string, body: unknown) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });

const NVD = {
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-0001',
        published: '2024-01-02T10:00:00.000',
        descriptions: [{ lang: 'en', value: 'PostgreSQL authentication bypass' }],
        metrics: {
          cvssMetricV31: [
            {
              type: 'Primary',
              cvssData: {
                version: '3.1',
                baseScore: 9.8,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              },
            },
          ],
        },
        weaknesses: [{ description: [{ lang: 'en', value: 'CWE-287' }] }],
      },
    },
    {
      cve: {
        id: 'CVE-2024-0002',
        descriptions: [{ lang: 'en', value: 'minor issue' }],
        metrics: {
          cvssMetricV31: [
            { cvssData: { version: '3.1', baseScore: 3.1, vectorString: 'CVSS:3.1/x' } },
          ],
        },
      },
    },
  ],
};
const KEV = {
  vulnerabilities: [
    {
      cveID: 'CVE-2024-0001',
      vulnerabilityName: 'PostgreSQL Auth Bypass',
      shortDescription: 'exploited',
      dateAdded: '2024-03-01',
      dueDate: '2024-03-22',
    },
  ],
};

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, network_segments, vulnerability_catalog cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['noc@test.local', 'noc_operator'],
    ['blue@test.local', 'blue_team_engineer'],
    ['analyst@test.local', 'soc_analyst'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [noc, blue, analyst] = (await Promise.all(
    ['noc', 'blue', 'analyst'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string];
});

describe('vulnerability catalogue', () => {
  it('imports NVD and KEV feeds, merges by CVE, enriches findings and the asset risk profile, and reports the capability', async () => {
    // A finding referencing a CVE the catalogue does not know yet.
    const asset = (
      await jsonOf(
        await post('/api/v1/assets/observations', noc, {
          source: 'test',
          method: 'passive_observation',
          observedAt: new Date().toISOString(),
          identifiers: {
            macAddresses: ['aa:aa:aa:aa:aa:11'],
            ipAddresses: ['10.9.0.10'],
            hostnames: ['db-09'],
          },
          attributes: {},
        }),
      )
    ).assetId as string;
    await h.handle.db.execute(
      sql`insert into vulnerability_findings (asset_id, title, severity, description, cve, validated) values (${asset}::uuid, 'PostgreSQL exposed', 'high', 'test', ARRAY['CVE-2024-0001','CVE-2099-9999']::text[], true)`,
    );
    const statusBefore = PlatformStatus.parse(
      await jsonOf(await get('/api/v1/platform/status', admin.token)),
    );
    expect(statusBefore.capabilities.find((c) => c.id === 'vuln.catalog')).toMatchObject({
      state: 'not_configured',
    });
    const stats0 = await jsonOf(await get('/api/v1/vulnerabilities/stats', analyst));
    expect(stats0).toMatchObject({ total: 0, uncatalogued: ['CVE-2024-0001', 'CVE-2099-9999'] });

    // Permissions: analysts read, only threat_intel.manage imports.
    expect(
      (
        await post('/api/v1/vulnerabilities/import', analyst, {
          format: 'nvd_2',
          content: JSON.stringify(NVD),
        })
      ).status,
    ).toBe(403);
    const imp = await jsonOf(
      await post('/api/v1/vulnerabilities/import', blue, {
        format: 'nvd_2',
        content: JSON.stringify(NVD),
      }),
    );
    expect(imp).toMatchObject({
      parsed: 2,
      imported: 2,
      updated: 0,
      unchanged: 0,
      findingsEnriched: 1,
      errorCount: 0,
    });
    // Re-import is idempotent.
    expect(
      await jsonOf(
        await post('/api/v1/vulnerabilities/import', blue, {
          format: 'nvd_2',
          content: JSON.stringify(NVD),
        }),
      ),
    ).toMatchObject({ imported: 0, updated: 0, unchanged: 2, findingsEnriched: 0 });
    // KEV merges: exploited flag set, CVSS from NVD preserved.
    const kev = await jsonOf(
      await post('/api/v1/vulnerabilities/import', blue, {
        format: 'cisa_kev',
        content: JSON.stringify(KEV),
      }),
    );
    expect(kev).toMatchObject({ parsed: 1, imported: 0, updated: 1 });
    const rec = VulnerabilityRecord.parse(
      await jsonOf(await get('/api/v1/vulnerabilities/CVE-2024-0001', analyst)),
    );
    expect(rec).toMatchObject({
      cvssBaseScore: 9.8,
      cwe: ['CWE-287'],
      knownExploited: true,
      kevDueAt: '2024-03-22T00:00:00.000Z',
      sources: ['nvd_2', 'cisa_kev'],
    });
    expect((await get('/api/v1/vulnerabilities/CVE-2000-0000', analyst)).status).toBe(404);
    expect((await get('/api/v1/vulnerabilities/nope', analyst)).status).toBe(400);
    const list = await jsonOf(await get('/api/v1/vulnerabilities?knownExploited=true', analyst));
    expect(list.items.map((v: { cveId: string }) => v.cveId)).toEqual(['CVE-2024-0001']);
    expect(
      (await jsonOf(await get('/api/v1/vulnerabilities?q=minor', analyst))).items[0].cveId,
    ).toBe('CVE-2024-0002');
    // Feed rejected outright when nothing parses.
    const bad = await post('/api/v1/vulnerabilities/import', blue, {
      format: 'nvd_2',
      content: '{"vulnerabilities":[{"cve":{"id":"x"}}]}',
    });
    expect(bad.status).toBe(422);

    // The finding now carries the CVSS from the catalogue and the attached record; the unknown CVE stays uncatalogued.
    const f = FindingRecord.parse(
      (await jsonOf(await get(`/api/v1/findings?assetId=${asset}`, analyst))).items[0],
    );
    expect(f.cvssBaseScore).toBe(9.8);
    expect(f.cvssVector).toMatch(/^CVSS:3.1/);
    expect(f.vulnerabilities.map((v) => v.cveId)).toEqual(['CVE-2024-0001']);
    expect(f.vulnerabilities[0]!.knownExploited).toBe(true);
    expect(
      (await jsonOf(await get('/api/v1/vulnerabilities/stats', analyst))).uncatalogued,
    ).toEqual(['CVE-2099-9999']);

    // Risk profile and graph node reflect exploitation in the wild.
    const p = AssetRiskProfile.parse(
      await jsonOf(await get(`/api/v1/assets/${asset}/risk`, analyst)),
    );
    expect(p.findings[0]!.vulnerabilities[0]).toMatchObject({
      cveId: 'CVE-2024-0001',
      knownExploited: true,
    });
    expect(p.risk.basis.join(' ')).toMatch(/exploitation observed in the wild/);
    expect(p.risk.basis.join(' ')).toMatch(/9.0 or higher/);
    expect(['high', 'critical']).toContain(p.risk.level);
    const g = await jsonOf(await get('/api/v1/assets/graph', analyst));
    expect(g.nodes[0].risk.basis.join(' ')).toMatch(/exploitation observed in the wild/);

    const status = PlatformStatus.parse(
      await jsonOf(await get('/api/v1/platform/status', admin.token)),
    );
    expect(status.capabilities.find((c) => c.id === 'vuln.catalog')).toMatchObject({
      state: 'available',
    });
    expect(status.capabilities.find((c) => c.id === 'vuln.catalog')!.reason).toMatch(
      /2 CVE\(s\) catalogued, 1 known exploited/,
    );
    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    expect(
      audit.items.filter((e: { action: string }) => e.action === 'vulnerabilities.import'),
    ).toHaveLength(3);
  });
});
