import http from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { MlScoreRecord, MlStatus, PlatformStatus } from '@noc/shared';
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

/**
 * Stand-in for the analysis service with the real contract: status register, 422 on short history,
 * score = max |z|-squash over features. Keeps the API tests independent of a Python process.
 */
function stubAnalysis(): Promise<{ server: http.Server; url: string; calls: unknown[] }> {
  const calls: unknown[] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/api/v1/analysis/status') {
        res.end(
          JSON.stringify({
            service: 'noc-analysis',
            environment: 'test',
            advisory_only: true,
            external_model_apis_allowed: false,
            models: [
              {
                name: 'robust-baseline',
                version: '1.0.0',
                state: 'advisory',
                kind: 'statistical_baseline',
                evaluation: 'none: unsupervised baseline',
                min_history_points: 12,
              },
            ],
          }),
        );
        return;
      }
      if (req.url === '/api/v1/analysis/score') {
        const b = JSON.parse(body) as {
          subject_id: string;
          feature_set_version: string;
          features: Array<{ name: string; history: number[]; current: number }>;
        };
        calls.push(b);
        const short = b.features.find((f) => f.history.length < 12);
        if (short) {
          res.statusCode = 422;
          res.end(
            JSON.stringify({
              detail: {
                code: 'insufficient_history',
                feature: short.name,
                points: short.history.length,
                required: 12,
              },
            }),
          );
          return;
        }
        const explanation = b.features.map((f) => {
          const med = [...f.history].sort((x, y) => x - y)[Math.floor(f.history.length / 2)]!;
          const z = (f.current - med) / Math.max(1, Math.abs(med) * 0.05);
          return { feature: f.name, contribution: 0, current: f.current, median: med, mad: 0, z };
        });
        const squash = (z: number) => Math.abs(z) / (Math.abs(z) + 4);
        const total = explanation.reduce((a, e) => a + squash(e.z), 0) || 1;
        for (const e of explanation) e.contribution = squash(e.z) / total;
        res.end(
          JSON.stringify({
            model_name: 'robust-baseline',
            model_version: '1.0.0',
            feature_set_version: b.feature_set_version,
            subject_type: 'asset',
            subject_id: b.subject_id,
            score: Math.max(...explanation.map((e) => squash(e.z))),
            advisory: true,
            explanation,
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({
        server,
        url: `http://127.0.0.1:${(server.address() as { port: number }).port}`,
        calls,
      }),
    ),
  );
}

let stub: Awaited<ReturnType<typeof stubAnalysis>>;
let h: Harness;
let admin: { token: string };
let blue: string; // ml.read + ml.manage
let analyst: string; // no ml permissions
let noc: string; // assets.manage: seeds inventory observations
const PW = 'ml-password-that-is-long-enough';

beforeAll(async () => {
  stub = await stubAnalysis();
  h = await createHarness({ ANALYSIS_URL: stub.url });
});
afterAll(async () => {
  await h.close();
  stub.server.close();
});
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(sql`truncate table security_events cascade`);
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'blue@test.local',
    password: PW,
    roles: ['blue_team_engineer'],
  });
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
  noc = (await login(h, 'noc@test.local', PW)).body.accessToken;
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken;
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
});

async function seedAsset(): Promise<string> {
  const r = await h.app.request('/api/v1/assets/observations', {
    method: 'POST',
    headers: authed(noc),
    body: JSON.stringify({
      source: 'test',
      method: 'passive_observation',
      observedAt: new Date().toISOString(),
      identifiers: {
        macAddresses: ['aa:bb:cc:dd:ee:01'],
        ipAddresses: ['10.0.0.9'],
        hostnames: ['ws-09'],
      },
      attributes: {},
    }),
  });
  return (await jsonOf(r)).assetId;
}

async function seedEvents(assetId: string, perHour: number, hours: number, spikeNow: number) {
  const values: string[] = [];
  const now = Date.now();
  for (let hAgo = 1; hAgo <= hours; hAgo++)
    for (let i = 0; i < perHour; i++)
      values.push(
        `(gen_random_uuid(), '1.0', to_timestamp(${Math.floor((now - hAgo * 3_600_000) / 1000)}), 'suricata', 'network', 'flow', 'info', '10.0.0.9'::inet, '10.0.1.${(i % 200) + 1}'::inet, 443, '${assetId}'::uuid, 'h-${hAgo}-${i}')`,
      );
  for (let i = 0; i < spikeNow; i++)
    values.push(
      `(gen_random_uuid(), '1.0', now(), 'suricata', 'network', 'flow', 'info', '10.0.0.9'::inet, '10.0.2.${(i % 200) + 1}'::inet, ${1000 + i}, '${assetId}'::uuid, 'now-${i}')`,
    );
  for (let i = 0; i < values.length; i += 500)
    await h.handle.db.execute(
      sql.raw(
        `insert into security_events (id, schema_version, event_time, source_product, category, type, severity, src_ip, dst_ip, dst_port, src_asset_id, dedup_hash) values ${values.slice(i, i + 500).join(',')}`,
      ),
    );
}

describe('advisory ML scoring', () => {
  it('reports the analysis service honestly and keeps results read-only for ml.read holders', async () => {
    expect((await h.app.request('/api/v1/ml/status', { headers: authed(analyst) })).status).toBe(
      403,
    );
    const st = MlStatus.parse(
      await jsonOf(await h.app.request('/api/v1/ml/status?fresh=true', { headers: authed(blue) })),
    );
    expect(st).toMatchObject({
      reachable: true,
      advisoryOnly: true,
      externalModelApisAllowed: false,
      resultCount: 0,
    });
    expect(st.models[0]).toMatchObject({
      name: 'robust-baseline',
      kind: 'statistical_baseline',
      state: 'advisory',
    });
    const ps = PlatformStatus.parse(
      await jsonOf(
        await h.app.request('/api/v1/platform/status', { headers: authed(admin.token) }),
      ),
    );
    expect(ps.capabilities.find((c) => c.id === 'ml.analytics')).toMatchObject({
      state: 'available',
    });
    expect(ps.capabilities.find((c) => c.id === 'ml.analytics')?.reason).toMatch(/Advisory only/);
  });

  it('builds hourly features from the event store, scores a spike high, stores an explanation and audits it', async () => {
    const assetId = await seedAsset();
    expect(
      (
        await h.app.request('/api/v1/ml/score', {
          method: 'POST',
          headers: authed(blue),
          body: JSON.stringify({ subjectType: 'asset', subjectId: assetId }),
        })
      ).status,
    ).toBe(422); // no events
    await seedEvents(assetId, 5, 168, 300); // full window: quiet hours would otherwise pull the median to 0
    const res = await h.app.request('/api/v1/ml/score', {
      method: 'POST',
      headers: authed(blue),
      body: JSON.stringify({ subjectType: 'asset', subjectId: assetId }),
    });
    expect(res.status).toBe(201);
    const r = MlScoreRecord.parse(await jsonOf(res));
    expect(r).toMatchObject({
      subjectType: 'asset',
      subjectId: assetId,
      advisory: true,
      modelName: 'robust-baseline',
      featureSetVersion: 'asset-hourly-v1',
    });
    expect(r.score).toBeGreaterThan(0.9);
    expect(r.features.map((f) => f.feature)).toEqual([
      'events',
      'distinct_dst_ports',
      'distinct_peers',
      'detections',
    ]);
    expect(r.features.find((f) => f.feature === 'events')).toMatchObject({
      current: 300,
      median: 5,
    });
    expect(Math.abs(r.explanation.reduce((a, e) => a + e.contribution, 0) - 1)).toBeLessThan(1e-6);
    const sent = stub.calls[stub.calls.length - 1] as { features: Array<{ history: number[] }> };
    expect(sent.features[0]!.history).toHaveLength(168); // quiet hours are explicit zeros
    expect((await h.app.request('/api/v1/ml/results', { headers: authed(analyst) })).status).toBe(
      403,
    );
    const list = await jsonOf(
      await h.app.request(`/api/v1/ml/results?subjectId=${assetId}&minScore=0.5`, {
        headers: authed(blue),
      }),
    );
    expect(list.items).toHaveLength(1);
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=20', { headers: authed(admin.token) }),
    );
    expect(
      audit.items.find((e: { action: string }) => e.action === 'ml.score').metadata,
    ).toMatchObject({ advisory: true });
    // Nothing acted on the score: no alert, no incident, no response action was created.
    expect(
      (await jsonOf(await h.app.request('/api/v1/alerts', { headers: authed(analyst) }))).items,
    ).toHaveLength(0);
    expect(
      (await jsonOf(await h.app.request('/api/v1/incidents', { headers: authed(analyst) }))).items,
    ).toHaveLength(0);
    // Batch scoring reports skips instead of hiding them.
    const batch = await jsonOf(
      await h.app.request('/api/v1/ml/score/batch', {
        method: 'POST',
        headers: authed(blue),
        body: JSON.stringify({ limit: 10 }),
      }),
    );
    expect(batch.scored).toBe(1);
    expect(batch.skipped).toEqual([]);
  });

  it('turns an unreachable analysis service into a reported state, not a crash', async () => {
    const h2 = await createHarness({ ANALYSIS_URL: 'http://127.0.0.1:9' });
    try {
      await seedAdmin(h2);
      const a = await loginAdmin(h2);
      await createUser(h2, a.token, {
        email: 'blue2@test.local',
        password: PW,
        roles: ['blue_team_engineer'],
      });
      await createUser(h2, a.token, {
        email: 'noc2@test.local',
        password: PW,
        roles: ['noc_operator'],
      });
      const b = (await login(h2, 'blue2@test.local', PW)).body.accessToken;
      const n2 = (await login(h2, 'noc2@test.local', PW)).body.accessToken;
      const st = MlStatus.parse(
        await jsonOf(await h2.app.request('/api/v1/ml/status?fresh=true', { headers: authed(b) })),
      );
      expect(st).toMatchObject({ reachable: false, models: [] });
      expect(st.detail).toBeTruthy();
      const ps = PlatformStatus.parse(
        await jsonOf(await h2.app.request('/api/v1/platform/status', { headers: authed(a.token) })),
      );
      expect(ps.capabilities.find((c) => c.id === 'ml.analytics')).toMatchObject({
        state: 'not_configured',
      });
      const assetId = await (async () => {
        const r = await h2.app.request('/api/v1/assets/observations', {
          method: 'POST',
          headers: authed(n2),
          body: JSON.stringify({
            source: 'test',
            method: 'passive_observation',
            observedAt: new Date().toISOString(),
            identifiers: {
              macAddresses: ['aa:bb:cc:dd:ee:02'],
              ipAddresses: ['10.0.0.10'],
              hostnames: ['ws-10'],
            },
            attributes: {},
          }),
        });
        return (await jsonOf(r)).assetId as string;
      })();
      await h2.handle.db.execute(
        sql`insert into security_events (id, schema_version, event_time, source_product, category, type, severity, src_asset_id, dedup_hash) values (gen_random_uuid(), '1.0', now(), 'suricata', 'network', 'flow', 'info', ${assetId}::uuid, 'u-1')`,
      );
      expect(
        (
          await h2.app.request('/api/v1/ml/score', {
            method: 'POST',
            headers: authed(b),
            body: JSON.stringify({ subjectType: 'asset', subjectId: assetId }),
          })
        ).status,
      ).toBe(503);
    } finally {
      await h2.close();
    }
  });
});
