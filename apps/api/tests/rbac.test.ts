import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  authed,
  createHarness,
  createUser,
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

const PW = 'another-sufficiently-long-password';

describe('authorization (deny by default)', () => {
  it('unauthenticated requests to sensitive routes get 401, not 403 or 200', async () => {
    for (const path of [
      '/api/v1/users',
      '/api/v1/roles',
      '/api/v1/platform/status',
      '/api/v1/audit',
    ]) {
      expect((await h.app.request(path)).status, path).toBe(401);
    }
  });

  it('admin can create users; read-only auditor cannot', async () => {
    const { token } = await loginAdmin(h);
    const created = await createUser(h, token, {
      email: 'auditor@test.local',
      password: PW,
      roles: ['read_only_auditor'],
    });
    expect(created.res.status).toBe(201);
    expect(created.body.roles).toEqual(['read_only_auditor']);
    expect(JSON.stringify(created.body)).not.toMatch(/password/i);

    const aud = await login(h, 'auditor@test.local', PW);
    expect(aud.res.status).toBe(200);
    const denied = await createUser(h, aud.body.accessToken, {
      email: 'x@test.local',
      password: PW,
      roles: [],
    });
    expect(denied.res.status).toBe(403);
    expect(denied.body.error.code).toBe('forbidden');
  });

  it('a user with no roles can authenticate but reach nothing sensitive', async () => {
    const { token } = await loginAdmin(h);
    await createUser(h, token, { email: 'norole@test.local', password: PW, roles: [] });
    const r = await login(h, 'norole@test.local', PW);
    expect(r.res.status).toBe(200);
    expect(r.body.user.permissions).toEqual([]);
    expect(
      (await h.app.request('/api/v1/platform/status', { headers: authed(r.body.accessToken) }))
        .status,
    ).toBe(403);
    expect(
      (await h.app.request('/api/v1/users', { headers: authed(r.body.accessToken) })).status,
    ).toBe(403);
  });

  it('role changes invalidate outstanding tokens and cannot target oneself', async () => {
    const admin = await loginAdmin(h);
    const created = await createUser(h, admin.token, {
      email: 'soc@test.local',
      password: PW,
      roles: ['soc_analyst'],
    });
    const soc = await login(h, 'soc@test.local', PW);
    expect(
      (await h.app.request('/api/v1/platform/status', { headers: authed(soc.body.accessToken) }))
        .status,
    ).toBe(200);

    const demote = await h.app.request(`/api/v1/users/${created.body.id}/roles`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ roles: [] }),
    });
    expect(demote.status).toBe(200);
    expect(
      (await h.app.request('/api/v1/auth/me', { headers: authed(soc.body.accessToken) })).status,
    ).toBe(401);

    const self = await h.app.request(`/api/v1/users/${admin.user.id}/roles`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ roles: [] }),
    });
    expect(self.status).toBe(403);
  });

  it('disabling a user ends their sessions and blocks login', async () => {
    const admin = await loginAdmin(h);
    const created = await createUser(h, admin.token, {
      email: 'tmp@test.local',
      password: PW,
      roles: ['noc_operator'],
    });
    const tmp = await login(h, 'tmp@test.local', PW);
    const r = await h.app.request(`/api/v1/users/${created.body.id}/status`, {
      method: 'PUT',
      headers: authed(admin.token),
      body: JSON.stringify({ status: 'disabled' }),
    });
    expect(r.status).toBe(200);
    expect(
      (await h.app.request('/api/v1/auth/me', { headers: authed(tmp.body.accessToken) })).status,
    ).toBe(401);
    expect((await login(h, 'tmp@test.local', PW)).res.status).toBe(401);
  });

  it('rejects unknown role keys and unknown body fields', async () => {
    const { token } = await loginAdmin(h);
    const badRole = await createUser(h, token, {
      email: 'a@test.local',
      password: PW,
      roles: ['superuser'],
    });
    expect(badRole.res.status).toBe(400);
    const extra = await h.app.request('/api/v1/users', {
      method: 'POST',
      headers: authed(token),
      body: JSON.stringify({
        email: 'b@test.local',
        displayName: 'b',
        password: PW,
        roles: [],
        isAdmin: true,
      }),
    });
    expect(extra.status).toBe(400);
  });

  it('role catalogue is readable only with roles.read', async () => {
    const { token } = await loginAdmin(h);
    const r = await h.app.request('/api/v1/roles', { headers: authed(token) });
    expect(r.status).toBe(200);
    const roles = await jsonOf(r);
    expect(roles.map((x: { key: string }) => x.key)).toContain('red_team_operator');
  });
});
