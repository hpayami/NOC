import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PlatformStatus } from '@noc/shared';
import {
  authed,
  createHarness,
  login,
  loginAdmin,
  resetDatabase,
  seedAdmin,
  ADMIN,
  type Harness,
  jsonOf,
} from './helpers';

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  h.limiter.reset();
  await seedAdmin(h);
});

describe('platform endpoints', () => {
  it('health and readiness are public and honest', async () => {
    const health = await h.app.request('/health');
    expect(health.status).toBe(200);
    expect(health.headers.get('x-request-id')).toMatch(/[0-9a-f-]{36}/);
    const ready = await h.app.request('/ready');
    expect(ready.status).toBe(200);
    expect(await jsonOf(ready)).toEqual({ status: 'ready', database: 'available' });
  });

  it('status conforms to the shared contract and claims nothing operational', async () => {
    const { token } = await loginAdmin(h);
    const r = await h.app.request('/api/v1/platform/status', { headers: authed(token) });
    expect(r.status).toBe(200);
    const body = PlatformStatus.parse(await jsonOf(r));
    expect(body.demoData).toBe(false);
    expect(body.database.migrationsApplied).toBeGreaterThan(0);
    const available = body.capabilities.filter((c) => c.state === 'available').map((c) => c.id);
    expect(available).toEqual([
      'auth.rbac',
      'audit.tamper_evident',
      'asset.inventory',
      'asset.discovery.passive',
      'asset.discovery.active',
      'noc.health_monitoring',
      'network.topology',
      'events.pipeline',
      'soc.alerts',
      'soc.incidents',
      'data.retention',
      'response.actions',
      'detection.rule_registry',
    ]);
    expect(body.capabilities.find((c) => c.id === 'nips.inline_prevention')?.state).toBe(
      'disabled',
    );
    for (const m of body.metrics) {
      if (m.sourceState !== 'available') expect(m.value).toBeNull();
    }
    expect(body.metrics.find((m) => m.id === 'assets.total')?.value).toBe(0);
  });

  it('metrics require a static token or platform.metrics.read', async () => {
    expect((await h.app.request('/metrics')).status).toBe(401);
    expect(
      (
        await h.app.request('/metrics', {
          headers: { authorization: 'Bearer wrong-token-wrong-token-wrong' },
        })
      ).status,
    ).toBe(401);
    const ok = await h.app.request('/metrics', {
      headers: { authorization: `Bearer ${h.env.METRICS_TOKEN}` },
    });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toMatch(/noc_api_http_requests_total/);
    const { token } = await loginAdmin(h);
    expect((await h.app.request('/metrics', { headers: authed(token) })).status).toBe(200);
  });

  it('serves an OpenAPI document', async () => {
    const r = await h.app.request('/api/v1/openapi.json');
    expect(r.status).toBe(200);
    const doc = await jsonOf(r);
    expect(doc.openapi).toBe('3.1.0');
    expect(Object.keys(doc.paths)).toContain('/api/v1/auth/login');
    expect(Object.keys(doc.paths)).toContain('/api/v1/platform/status');
  });

  it('enforces body size limits and rate limits', async () => {
    const big = await h.app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b.co', password: 'x'.repeat(300_000) }),
    });
    expect(big.status).toBe(413);

    h.limiter.reset();
    let limited = 0;
    for (let i = 0; i < 12; i++) {
      const r = await login(h, ADMIN.email, 'wrong-password-but-long-enough');
      if (r.res.status === 429) limited++;
    }
    expect(limited).toBeGreaterThan(0);
  });

  it('returns structured 404s and never leaks stack traces', async () => {
    const r = await h.app.request('/api/v1/does-not-exist');
    expect(r.status).toBe(404);
    const body = await jsonOf(r);
    expect(body.error.code).toBe('not_found');
    expect(body.error.requestId).toBeTruthy();
  });

  it('rejects disallowed CORS origins', async () => {
    const r = await h.app.request('/health', { headers: { origin: 'https://evil.example' } });
    expect(r.headers.get('access-control-allow-origin')).toBeNull();
    const ok = await h.app.request('/health', { headers: { origin: 'http://localhost:3000' } });
    expect(ok.headers.get('access-control-allow-origin')).toBe('http://localhost:3000');
  });
});
