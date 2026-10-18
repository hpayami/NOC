import http from 'node:http';
import {
  createHash,
  createSign,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { PlatformStatus, TokenResponse } from '@noc/shared';
import {
  ADMIN,
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

const b64 = (b: Buffer) => b.toString('base64url');

/** Minimal OIDC provider: discovery, JWKS, token endpoint that enforces PKCE and mints RS256 ID tokens. */
function mockIdp() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rogue = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
  const codes = new Map<
    string,
    { challenge: string; claims: Record<string, unknown>; signer: KeyObject; alg: string }
  >();
  let issuer = '';
  const sign = (claims: Record<string, unknown>, signer: KeyObject, alg = 'RS256') => {
    const header = b64(Buffer.from(JSON.stringify({ alg, kid: 'k1', typ: 'JWT' })));
    const payload = b64(Buffer.from(JSON.stringify(claims)));
    if (alg === 'none') return `${header}.${payload}.`;
    const s = createSign('sha256').update(`${header}.${payload}`).sign(signer);
    return `${header}.${payload}.${b64(s)}`;
  };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/.well-known/openid-configuration') {
        res.end(
          JSON.stringify({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            jwks_uri: `${issuer}/jwks`,
            end_session_endpoint: `${issuer}/logout`,
          }),
        );
        return;
      }
      if (req.url === '/jwks') {
        res.end(
          JSON.stringify({
            keys: [{ kty: 'RSA', kid: 'k1', use: 'sig', alg: 'RS256', n: jwk.n, e: jwk.e }],
          }),
        );
        return;
      }
      if (req.url === '/token') {
        const form = new URLSearchParams(body);
        const entry = codes.get(form.get('code') ?? '');
        const verifier = form.get('code_verifier') ?? '';
        if (
          !entry ||
          b64(createHash('sha256').update(verifier).digest()) !== entry.challenge ||
          form.get('grant_type') !== 'authorization_code'
        ) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        codes.delete(form.get('code')!);
        res.end(
          JSON.stringify({
            access_token: 'opaque',
            token_type: 'Bearer',
            id_token: sign(entry.claims, entry.signer, entry.alg),
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  return {
    server,
    privateKey,
    rogue,
    /** Mints a token the IdP would send out of band (back-channel logout). */
    sign(claims: Record<string, unknown>, over: { signer?: KeyObject; alg?: string } = {}) {
      return sign(claims, over.signer ?? privateKey, over.alg ?? 'RS256');
    },
    get issuer() {
      return issuer;
    },
    start: () =>
      new Promise<string>((r) =>
        server.listen(0, '127.0.0.1', () =>
          r((issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`)),
        ),
      ),
    /** Simulates the user authenticating at the IdP: returns the code the browser would bring back. */
    authorize(
      authorizationUrl: string,
      claims: Record<string, unknown>,
      over: { signer?: KeyObject; alg?: string } = {},
    ) {
      const u = new URL(authorizationUrl);
      expect(u.searchParams.get('code_challenge_method')).toBe('S256');
      expect(u.searchParams.get('response_type')).toBe('code');
      const code = b64(randomBytes(16));
      const now = Math.floor(Date.now() / 1000);
      codes.set(code, {
        challenge: u.searchParams.get('code_challenge')!,
        claims: {
          iss: issuer,
          aud: u.searchParams.get('client_id'),
          iat: now,
          exp: now + 300,
          nonce: u.searchParams.get('nonce'),
          ...claims,
        },
        signer: over.signer ?? privateKey,
        alg: over.alg ?? 'RS256',
      });
      return { code, state: u.searchParams.get('state')! };
    },
  };
}

let idp: ReturnType<typeof mockIdp>;
let issuer: string;
let h: Harness;
const PUBLIC = { 'content-type': 'application/json', origin: 'http://localhost:3000' };
const start = async (app: Harness['app']) =>
  jsonOf(await app.request('/api/v1/auth/oidc/start', { method: 'POST', headers: PUBLIC }));
const callback = (app: Harness['app'], body: unknown) =>
  app.request('/api/v1/auth/oidc/callback', {
    method: 'POST',
    headers: PUBLIC,
    body: JSON.stringify(body),
  });

beforeAll(async () => {
  idp = mockIdp();
  issuer = await idp.start();
  h = await createHarness({
    OIDC_ISSUER: issuer,
    OIDC_CLIENT_ID: 'noc-web',
    OIDC_REDIRECT_URI: 'http://localhost:3000/auth/oidc/callback',
    OIDC_ROLE_MAP: JSON.stringify({
      'sec-analysts': 'soc_analyst',
      'ir-team': 'incident_responder',
    }),
    OIDC_DEFAULT_ROLES: 'read_only_auditor',
    OIDC_DISPLAY_NAME: 'Corp IdP',
    OIDC_POST_LOGOUT_REDIRECT_URI: 'http://localhost:3000/login?reason=signed_out',
  });
});
afterAll(async () => {
  await h.close();
  idp.server.close();
});
beforeEach(async () => {
  await resetDatabase(h.handle);
  h.limiter.reset();
  await seedAdmin(h);
});

describe('OIDC single sign-on', () => {
  it('advertises the provider, starts with PKCE, and refuses forged, replayed or stale logins', async () => {
    const providers = await jsonOf(await h.app.request('/api/v1/auth/providers'));
    expect(providers).toEqual({
      local: true,
      oidc: {
        enabled: true,
        displayName: 'Corp IdP',
        jitProvisioning: true,
        rpInitiatedLogout: true,
      },
    });
    const admin = await loginAdmin(h);
    const ps = PlatformStatus.parse(
      await jsonOf(
        await h.app.request('/api/v1/platform/status', { headers: authed(admin.token) }),
      ),
    );
    expect(ps.capabilities.find((c) => c.id === 'auth.sso')).toMatchObject({ state: 'available' });

    const s = await start(h.app);
    expect(s.authorizationUrl).toContain(`${issuer}/authorize?`);
    expect(s.state).toHaveLength(43);
    // Unknown state.
    expect((await callback(h.app, { code: 'x', state: 'a'.repeat(43) })).status).toBe(401);
    // Token signed by a key the IdP never published.
    const forged = idp.authorize(
      s.authorizationUrl,
      { sub: 'u-1', email: 'alice@corp.test', groups: ['sec-analysts'] },
      { signer: idp.rogue },
    );
    const r1 = await callback(h.app, forged);
    expect(r1.status).toBe(401);
    expect((await jsonOf(r1)).error.message).toMatch(/signature/);
    // The state was consumed by the failed attempt: it cannot be replayed.
    const s2 = await start(h.app);
    const replay = idp.authorize(s2.authorizationUrl, { sub: 'u-1', email: 'alice@corp.test' });
    expect((await callback(h.app, { code: replay.code, state: s.state })).status).toBe(401);
    // alg=none is never accepted.
    const s3 = await start(h.app);
    const none = idp.authorize(
      s3.authorizationUrl,
      { sub: 'u-1', email: 'alice@corp.test' },
      { alg: 'none' },
    );
    expect((await jsonOf(await callback(h.app, none))).error.message).toMatch(/RS256/);
    // Nonce must match the one issued for this state.
    const s4 = await start(h.app);
    const wrongNonce = idp.authorize(s4.authorizationUrl, {
      sub: 'u-1',
      email: 'alice@corp.test',
      nonce: 'other',
    });
    expect((await jsonOf(await callback(h.app, wrongNonce))).error.message).toMatch(/nonce/);
    // Expired token.
    const s5 = await start(h.app);
    const old = idp.authorize(s5.authorizationUrl, {
      sub: 'u-1',
      email: 'alice@corp.test',
      exp: Math.floor(Date.now() / 1000) - 600,
    });
    expect((await jsonOf(await callback(h.app, old))).error.message).toMatch(/expired/);
    // Wrong audience.
    const s6 = await start(h.app);
    const aud = idp.authorize(s6.authorizationUrl, {
      sub: 'u-1',
      email: 'alice@corp.test',
      aud: 'someone-else',
    });
    expect((await jsonOf(await callback(h.app, aud))).error.message).toMatch(/audience/);
    // Expired state record.
    const s7 = await start(h.app);
    await h.handle.db.execute(
      sql`update oidc_states set expires_at = now() - interval '1 second' where state = ${s7.state}`,
    );
    const late = idp.authorize(s7.authorizationUrl, { sub: 'u-1', email: 'alice@corp.test' });
    expect((await callback(h.app, late)).status).toBe(401);
    expect(
      (
        await jsonOf(await h.app.request('/api/v1/users', { headers: authed(admin.token) }))
      ).items.map((u: { email: string }) => u.email),
    ).toEqual([ADMIN.email]);
  });

  it('provisions first-time users from the role claim, keeps roles in sync, and never links local accounts by e-mail', async () => {
    const admin = await loginAdmin(h);
    const s = await start(h.app);
    const ok = await callback(
      h.app,
      idp.authorize(s.authorizationUrl, {
        sub: 'u-alice',
        email: 'alice@corp.test',
        name: 'Alice',
        groups: ['sec-analysts', 'unknown-group'],
      }),
    );
    expect(ok.status).toBe(200);
    const tok = TokenResponse.parse(await jsonOf(ok));
    expect(tok.user).toMatchObject({
      email: 'alice@corp.test',
      displayName: 'Alice',
      roles: ['soc_analyst'],
    });
    expect(tok.user.permissions).toContain('alerts.triage');
    expect(ok.headers.get('set-cookie')).toMatch(/noc_refresh=/);
    expect(
      (await h.app.request('/api/v1/auth/me', { headers: authed(tok.accessToken) })).status,
    ).toBe(200);
    // Password login is refused for SSO accounts regardless of what is typed.
    expect((await login(h, 'alice@corp.test', 'anything-long-enough-here')).res.status).toBe(401);

    // Second login: same account, roles follow the claim (responder now), old tokens invalidated.
    const s2 = await start(h.app);
    const again = TokenResponse.parse(
      await jsonOf(
        await callback(
          h.app,
          idp.authorize(s2.authorizationUrl, {
            sub: 'u-alice',
            email: 'alice@corp.test',
            groups: ['ir-team'],
          }),
        ),
      ),
    );
    expect(again.user.id).toBe(tok.user.id);
    expect(again.user.roles).toEqual(['incident_responder']);
    expect(
      (await h.app.request('/api/v1/auth/me', { headers: authed(tok.accessToken) })).status,
    ).toBe(401);
    // No mapped group → default roles.
    const s3 = await start(h.app);
    const bob = TokenResponse.parse(
      await jsonOf(
        await callback(
          h.app,
          idp.authorize(s3.authorizationUrl, {
            sub: 'u-bob',
            email: 'bob@corp.test',
            groups: ['nothing-mapped'],
          }),
        ),
      ),
    );
    expect(bob.user.roles).toEqual(['read_only_auditor']);

    // A local account with the same e-mail is never hijacked by an IdP identity.
    await createUser(h, admin.token, {
      email: 'carol@corp.test',
      password: 'carol-password-that-is-long-enough',
      roles: ['platform_admin'],
    });
    const s4 = await start(h.app);
    const collision = await callback(
      h.app,
      idp.authorize(s4.authorizationUrl, {
        sub: 'u-carol-idp',
        email: 'carol@corp.test',
        groups: ['sec-analysts'],
      }),
    );
    expect(collision.status).toBe(409);
    expect(
      (await login(h, 'carol@corp.test', 'carol-password-that-is-long-enough')).res.status,
    ).toBe(200); // local login intact
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin.token) }),
    );
    const acts = audit.items.map(
      (e: { action: string; outcome: string }) => `${e.action}:${e.outcome}`,
    );
    expect(acts).toEqual(
      expect.arrayContaining([
        'auth.oidc_provision:success',
        'auth.oidc_login:success',
        'auth.oidc_role_sync:success',
        'auth.oidc_login:denied',
        'auth.login:denied',
      ]),
    );
    // Users list shows the provider for administrators.
    const u = (
      await jsonOf(await h.app.request('/api/v1/users', { headers: authed(admin.token) }))
    ).items.find((x: { email: string }) => x.email === 'alice@corp.test');
    expect(u.authProvider).toBe('oidc');
  });

  it('refuses unknown identities when JIT provisioning is off, and reports SSO as not configured without settings', async () => {
    const strict = await createHarness({
      OIDC_ISSUER: issuer,
      OIDC_CLIENT_ID: 'noc-web',
      OIDC_REDIRECT_URI: 'http://localhost:3000/auth/oidc/callback',
      OIDC_ALLOW_JIT: 'false',
    });
    try {
      await seedAdmin(strict);
      const s = await start(strict.app);
      const r = await callback(
        strict.app,
        idp.authorize(s.authorizationUrl, { sub: 'u-dave', email: 'dave@corp.test' }),
      );
      expect(r.status).toBe(403);
    } finally {
      await strict.close();
    }
    const plain = await createHarness();
    try {
      await seedAdmin(plain);
      expect((await jsonOf(await plain.app.request('/api/v1/auth/providers'))).oidc.enabled).toBe(
        false,
      );
      expect(
        (await plain.app.request('/api/v1/auth/oidc/start', { method: 'POST', headers: PUBLIC }))
          .status,
      ).toBe(503);
    } finally {
      await plain.close();
    }
  });

  it('ends the IdP session on logout and honours back-channel logout by sid and by sub, refusing forged or replayed tokens', async () => {
    const ssoLogin = async (sid: string) => {
      const s = await start(h.app);
      const a = idp.authorize(s.authorizationUrl, {
        sub: 'u-9',
        email: 'nina@corp.test',
        groups: ['sec-analysts'],
        sid,
      });
      const res = await callback(h.app, a);
      expect(res.status).toBe(200);
      const body = TokenResponse.parse(await jsonOf(res));
      const refresh = /noc_refresh=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1];
      expect(refresh).toBeTruthy();
      return { access: body.accessToken, refresh: refresh! };
    };
    const me = (token: string) => h.app.request('/api/v1/auth/me', { headers: authed(token) });
    const refreshWith = (refresh: string) =>
      h.app.request('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { cookie: `noc_refresh=${refresh}`, origin: 'http://localhost:3000' },
      });
    const backchannel = (token: string) =>
      h.app.request('/api/v1/auth/oidc/backchannel-logout', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ logout_token: token }).toString(),
      });
    const logoutClaims = (over: Record<string, unknown>) => {
      const now = Math.floor(Date.now() / 1000);
      return {
        iss: idp.issuer,
        aud: 'noc-web',
        iat: now,
        exp: now + 120,
        jti: b64(randomBytes(12)),
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
        ...over,
      };
    };

    // RP-initiated logout: local session dies and the browser is sent to the IdP end-session endpoint.
    const first = await ssoLogin('sid-1');
    const out = await h.app.request('/api/v1/auth/logout', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${first.refresh}`, origin: 'http://localhost:3000' },
    });
    expect(out.status).toBe(200);
    const url = new URL((await jsonOf(out)).idpLogoutUrl);
    expect(url.origin + url.pathname).toBe(`${idp.issuer}/logout`);
    expect(url.searchParams.get('client_id')).toBe('noc-web');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe(
      'http://localhost:3000/login?reason=signed_out',
    );
    expect(url.searchParams.has('id_token_hint')).toBe(false); // ID tokens are never stored
    expect((await refreshWith(first.refresh)).status).toBe(401);
    // A local account's logout carries no IdP URL.
    const admin = await loginAdmin(h);
    const localOut = await h.app.request('/api/v1/auth/logout', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${admin.refresh}`, origin: 'http://localhost:3000' },
    });
    expect(await jsonOf(localOut)).toEqual({ idpLogoutUrl: null });

    // Back-channel logout by sid: that IdP session's refresh family dies; another session survives.
    const a = await ssoLogin('sid-a');
    const b = await ssoLogin('sid-b');
    expect((await backchannel(idp.sign(logoutClaims({ sid: 'sid-a' })))).status).toBe(200);
    expect((await refreshWith(a.refresh)).status).toBe(401);
    expect((await refreshWith(b.refresh)).status).toBe(200);
    expect((await me(b.access)).status).toBe(200);

    // Refusals: forged key, wrong audience, nonce present, missing event, stale, no sub/sid, alg=none.
    for (const [token, why] of [
      [idp.sign(logoutClaims({ sid: 'sid-b' }), { signer: idp.rogue }), 'signature'],
      [idp.sign(logoutClaims({ sid: 'sid-b', aud: 'other' })), 'audience'],
      [idp.sign(logoutClaims({ sid: 'sid-b', nonce: 'n' })), 'nonce'],
      [idp.sign(logoutClaims({ sid: 'sid-b', events: {} })), 'event'],
      [idp.sign(logoutClaims({ sid: 'sid-b', iat: Math.floor(Date.now() / 1000) - 3600 })), 'old'],
      [idp.sign(logoutClaims({})), 'sub nor sid'],
      [idp.sign(logoutClaims({ sid: 'sid-b' }), { alg: 'none' }), 'RS256'],
    ] as const) {
      const r = await backchannel(token);
      expect(r.status, why).toBe(400);
      expect((await jsonOf(r)).error.message).toMatch(new RegExp(why));
    }
    expect((await me(b.access)).status).toBe(200); // nothing above touched the live session

    // Back-channel logout by sub: every session of the subject ends, access tokens included.
    const subToken = idp.sign(logoutClaims({ sub: 'u-9' }));
    expect((await backchannel(subToken)).status).toBe(200);
    expect((await me(b.access)).status).toBe(401);
    expect((await refreshWith(b.refresh)).status).toBe(401);
    // Replay of the same token (same jti) is refused.
    const replay = await backchannel(subToken);
    expect(replay.status).toBe(400);
    expect((await jsonOf(replay)).error.message).toMatch(/already processed/);
    // Unknown subject: processed (200), nothing to revoke, still audited.
    expect((await backchannel(idp.sign(logoutClaims({ sub: 'nobody' })))).status).toBe(200);
    // Password login was never possible for this account; the user can sign in again via SSO.
    expect((await ssoLogin('sid-c')).access).toBeTruthy();

    const admin2 = await loginAdmin(h);
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin2.token) }),
    );
    const bc = audit.items.filter(
      (e: { action: string }) => e.action === 'auth.oidc_backchannel_logout',
    );
    expect(bc.map((e: { metadata: { matched: string } }) => e.metadata.matched).sort()).toEqual([
      'none',
      'sid',
      'sub',
    ]);
    expect(
      audit.items.some(
        (e: { action: string; metadata: { idpLogout?: boolean } }) =>
          e.action === 'auth.logout' && e.metadata.idpLogout === true,
      ),
    ).toBe(true);
  });
});
