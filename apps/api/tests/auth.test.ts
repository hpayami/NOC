import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import {
  ADMIN,
  authed,
  createHarness,
  login,
  loginAdmin,
  resetDatabase,
  seedAdmin,
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

describe('authentication', () => {
  it('issues an access token and an httpOnly refresh cookie on valid login', async () => {
    const r = await login(h, ADMIN.email, ADMIN.password);
    expect(r.res.status).toBe(200);
    expect(r.body.tokenType).toBe('Bearer');
    expect(r.body.user.roles).toEqual(['platform_admin']);
    expect(r.body.user.permissions).toContain('users.manage');
    expect(r.setCookie).toMatch(/HttpOnly/);
    expect(r.setCookie).toMatch(/SameSite=Strict/);
    expect(r.setCookie).toMatch(/Path=\/api\/v1\/auth/);
    expect(JSON.stringify(r.body)).not.toMatch(/passwordHash|\$argon2/);
  });

  it('rejects wrong password and unknown user identically', async () => {
    const bad = await login(h, ADMIN.email, 'wrong-password-but-long-enough');
    const unknown = await login(h, 'nobody@test.local', 'wrong-password-but-long-enough');
    expect(bad.res.status).toBe(401);
    expect(unknown.res.status).toBe(401);
    expect(bad.body.error.message).toBe(unknown.body.error.message);
  });

  it('locks the account after repeated failures and audits it', async () => {
    for (let i = 0; i < 10; i++) {
      h.limiter.reset();
      await login(h, ADMIN.email, 'wrong-password-but-long-enough');
    }
    h.limiter.reset();
    const r = await login(h, ADMIN.email, ADMIN.password);
    expect(r.res.status).toBe(401);
    const rows = (await h.handle.db.execute(
      sql`select action from audit_events where action = 'auth.lockout'`,
    )) as unknown as unknown[];
    expect(rows.length).toBe(1);
  });

  it('serves /me with a valid token and rejects garbage or missing tokens', async () => {
    const { token } = await loginAdmin(h);
    const ok = await h.app.request('/api/v1/auth/me', { headers: authed(token) });
    expect(ok.status).toBe(200);
    expect((await jsonOf(ok)).email).toBe(ADMIN.email);
    expect((await h.app.request('/api/v1/auth/me')).status).toBe(401);
    expect((await h.app.request('/api/v1/auth/me', { headers: authed('not.a.jwt') })).status).toBe(
      401,
    );
    expect(
      (await h.app.request('/api/v1/auth/me', { headers: authed(token.slice(0, -2) + 'xx') }))
        .status,
    ).toBe(401);
  });

  it('rotates refresh tokens and kills the family on reuse', async () => {
    const { refresh } = await loginAdmin(h);
    const first = await h.app.request('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${refresh}`, origin: 'http://localhost:3000' },
    });
    expect(first.status).toBe(200);
    const second = /noc_refresh=([^;]+)/.exec(first.headers.get('set-cookie') ?? '')?.[1];
    expect(second).toBeTruthy();
    expect(second).not.toBe(refresh);

    // Replay of the already-rotated token → reuse detected, whole family revoked.
    const replay = await h.app.request('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${refresh}`, origin: 'http://localhost:3000' },
    });
    expect(replay.status).toBe(401);
    const victim = await h.app.request('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${second}`, origin: 'http://localhost:3000' },
    });
    expect(victim.status).toBe(401);
    const rows = (await h.handle.db.execute(
      sql`select 1 from audit_events where action = 'auth.refresh_reuse_detected'`,
    )) as unknown as unknown[];
    expect(rows.length).toBe(1);
  });

  it('rejects cookie-based refresh from a non-allow-listed origin', async () => {
    const { refresh } = await loginAdmin(h);
    const r = await h.app.request('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${refresh}`, origin: 'https://evil.example' },
    });
    expect(r.status).toBe(401);
  });

  it('logout-all invalidates existing access tokens immediately', async () => {
    const { token } = await loginAdmin(h);
    expect(
      (await h.app.request('/api/v1/auth/logout-all', { method: 'POST', headers: authed(token) }))
        .status,
    ).toBe(204);
    expect((await h.app.request('/api/v1/auth/me', { headers: authed(token) })).status).toBe(401);
  });

  it('password change requires the current password and revokes sessions', async () => {
    const { token } = await loginAdmin(h);
    const bad = await h.app.request('/api/v1/auth/password', {
      method: 'POST',
      headers: authed(token),
      body: JSON.stringify({
        currentPassword: 'nope-nope-nope-nope',
        newPassword: 'a-brand-new-password-123',
      }),
    });
    expect(bad.status).toBe(401);
    const good = await h.app.request('/api/v1/auth/password', {
      method: 'POST',
      headers: authed(token),
      body: JSON.stringify({
        currentPassword: ADMIN.password,
        newPassword: 'a-brand-new-password-123',
      }),
    });
    expect(good.status).toBe(204);
    expect((await h.app.request('/api/v1/auth/me', { headers: authed(token) })).status).toBe(401);
    expect((await login(h, ADMIN.email, 'a-brand-new-password-123')).res.status).toBe(200);
  });

  it('refuses a second bootstrap once users exist', async () => {
    await expect(seedAdmin(h)).rejects.toThrow(/already exist/);
  });
});
