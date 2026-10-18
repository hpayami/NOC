import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { and, eq, isNull, sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import {
  ApiError,
  AuthProviders,
  LoginRequest,
  OidcCallbackRequest,
  OidcStartResponse,
  SessionUser,
  TokenResponse,
  type RoleKey,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { refreshTokens, users } from '../db/schema';
import { loadPrincipal, requireAuth, unauthorized } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';
import { hashPassword, verifyAgainstDummy, verifyPassword } from '../security/password';
import { generateRefreshToken, hashRefreshToken } from '../security/tokens';

export const REFRESH_COOKIE = 'noc_refresh';
const REFRESH_PATH = '/api/v1/auth';

const errorResponses = {
  400: { description: 'Validation failed', content: { 'application/json': { schema: ApiError } } },
  401: { description: 'Unauthenticated', content: { 'application/json': { schema: ApiError } } },
  429: { description: 'Rate limited', content: { 'application/json': { schema: ApiError } } },
};

export function authRoutes(deps: Deps) {
  const { db, env, tokens, audit, limiter, metrics, oidc } = deps;
  const app = new OpenAPIHono<AppEnv>();

  function setRefreshCookie(c: Parameters<typeof setCookie>[0], token: string) {
    setCookie(c, REFRESH_COOKIE, token, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: 'Strict',
      path: REFRESH_PATH,
      maxAge: env.AUTH_REFRESH_TTL_SECONDS,
    });
  }

  /** Cookie-authenticated endpoints must come from an allow-listed origin (CSRF defence in depth). */
  function assertTrustedOrigin(c: { req: { header: (n: string) => string | undefined } }) {
    const origin =
      c.req.header('origin') ??
      (c.req.header('referer') ? new URL(c.req.header('referer')!).origin : undefined);
    if (origin && !env.CORS_ALLOWED_ORIGINS.includes(origin))
      throw unauthorized('Origin not allowed');
  }

  async function issueSession(
    userId: string,
    roles: RoleKey[],
    tokenVersion: number,
    familyId: string,
    ip: string | null,
    ua: string | null,
  ) {
    const access = await tokens.issueAccessToken({ userId, roles, tokenVersion });
    const refresh = generateRefreshToken();
    const [row] = await db
      .insert(refreshTokens)
      .values({
        userId,
        familyId,
        tokenHash: refresh.hash,
        expiresAt: new Date(Date.now() + env.AUTH_REFRESH_TTL_SECONDS * 1000),
        createdIp: ip,
        userAgent: ua?.slice(0, 512) ?? null,
      })
      .returning({ id: refreshTokens.id });
    return { access, refresh, refreshRowId: row!.id };
  }

  const sessionUserOf = (p: NonNullable<AppEnv['Variables']['principal']>) =>
    SessionUser.parse({
      id: p.userId,
      email: p.email,
      displayName: p.displayName,
      roles: p.roles,
      permissions: [...p.permissions],
    });

  // ---- POST /login -------------------------------------------------------------------------
  const login = createRoute({
    method: 'post',
    path: '/login',
    tags: ['auth'],
    middleware: [
      rateLimit(limiter, { name: 'login', capacity: 10, refillPerSecond: 10 / 60 }),
    ] as const,
    request: {
      body: { content: { 'application/json': { schema: LoginRequest } }, required: true },
    },
    responses: {
      200: {
        description: 'Session issued',
        content: { 'application/json': { schema: TokenResponse } },
      },
      ...errorResponses,
    },
  });
  app.openapi(login, async (c) => {
    const { email, password } = c.req.valid('json');
    const ip = c.get('clientIp');
    const requestId = c.get('requestId');
    const deny = async (reason: string, userId: string | null = null) => {
      metrics.authFailures.inc({ reason });
      await audit.record({
        actorId: userId,
        actorLabel: email.toLowerCase(),
        action: 'auth.login',
        outcome: 'denied',
        requestId,
        sourceIp: ip,
        metadata: { reason },
      });
      throw unauthorized('Invalid credentials');
    };

    const [u] = await db
      .select()
      .from(users)
      .where(sql`lower(${users.email}) = lower(${email})`)
      .limit(1);
    if (!u) {
      await verifyAgainstDummy(password);
      return deny('unknown_user');
    }
    if (u.authProvider !== 'local') return deny('sso_account', u.id);
    if (u.status !== 'active') return deny('account_' + u.status, u.id);
    if (u.lockedUntil && u.lockedUntil.getTime() > Date.now()) return deny('locked', u.id);

    const ok = await verifyPassword(u.passwordHash, password);
    if (!ok) {
      const failed = u.failedLoginCount + 1;
      const lock = failed >= env.AUTH_MAX_FAILED_LOGINS;
      await db
        .update(users)
        .set({
          failedLoginCount: lock ? 0 : failed,
          lockedUntil: lock ? new Date(Date.now() + env.AUTH_LOCKOUT_SECONDS * 1000) : null,
          updatedAt: new Date(),
        })
        .where(eq(users.id, u.id));
      if (lock)
        await audit.record({
          actorId: u.id,
          actorLabel: u.email,
          action: 'auth.lockout',
          outcome: 'success',
          requestId,
          sourceIp: ip,
          metadata: { failed },
        });
      return deny('bad_password', u.id);
    }

    await db
      .update(users)
      .set({
        failedLoginCount: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(users.id, u.id));
    const principal = await loadPrincipal(db, u.id, u.tokenVersion, 'login');
    if (!principal) return deny('principal_unavailable', u.id);

    const { access, refresh } = await issueSession(
      u.id,
      principal.roles,
      u.tokenVersion,
      randomUUID(),
      ip,
      c.req.header('user-agent') ?? null,
    );
    await audit.record({
      actorId: u.id,
      actorLabel: u.email,
      action: 'auth.login',
      outcome: 'success',
      requestId,
      sourceIp: ip,
    });
    setRefreshCookie(c, refresh.token);
    return c.json(
      {
        accessToken: access.token,
        tokenType: 'Bearer' as const,
        expiresInSeconds: access.expiresIn,
        user: sessionUserOf(principal),
      },
      200,
    );
  });

  // ---- POST /refresh -----------------------------------------------------------------------
  const refresh = createRoute({
    method: 'post',
    path: '/refresh',
    tags: ['auth'],
    middleware: [
      rateLimit(limiter, { name: 'refresh', capacity: 30, refillPerSecond: 0.5 }),
    ] as const,
    responses: {
      200: { description: 'Rotated', content: { 'application/json': { schema: TokenResponse } } },
      ...errorResponses,
    },
  });
  app.openapi(refresh, async (c) => {
    assertTrustedOrigin(c);
    const raw = getCookie(c, REFRESH_COOKIE);
    if (!raw || raw.length > 128) throw unauthorized('Missing refresh token');
    const ip = c.get('clientIp');
    const requestId = c.get('requestId');
    const hash = hashRefreshToken(raw);

    const result = await db.transaction(async (tx) => {
      const [row] = await tx
        .select()
        .from(refreshTokens)
        .where(eq(refreshTokens.tokenHash, hash))
        .limit(1)
        .for('update');
      if (!row) return { kind: 'unknown' as const };
      if (row.revokedAt) {
        // A token that was *rotated* and is presented again was replayed (stolen or a broken
        // client): revoke the whole family. A token revoked by logout/family-kill is simply dead.
        if (row.replacedBy) {
          await tx
            .update(refreshTokens)
            .set({ revokedAt: new Date() })
            .where(and(eq(refreshTokens.familyId, row.familyId), isNull(refreshTokens.revokedAt)));
          await audit.record(
            {
              actorId: row.userId,
              actorLabel: row.userId,
              action: 'auth.refresh_reuse_detected',
              outcome: 'denied',
              requestId,
              sourceIp: ip,
              metadata: { familyId: row.familyId },
            },
            tx,
          );
          return { kind: 'reuse' as const };
        }
        return { kind: 'revoked' as const };
      }
      if (row.expiresAt.getTime() <= Date.now()) return { kind: 'expired' as const };
      const [u] = await tx.select().from(users).where(eq(users.id, row.userId)).limit(1);
      if (!u || u.status !== 'active') return { kind: 'inactive' as const };
      const principal = await loadPrincipal(db, u.id, u.tokenVersion, 'refresh');
      if (!principal) return { kind: 'inactive' as const };
      const next = generateRefreshToken();
      const [inserted] = await tx
        .insert(refreshTokens)
        .values({
          userId: u.id,
          familyId: row.familyId,
          tokenHash: next.hash,
          expiresAt: new Date(Date.now() + env.AUTH_REFRESH_TTL_SECONDS * 1000),
          createdIp: ip,
          userAgent: c.req.header('user-agent')?.slice(0, 512) ?? null,
        })
        .returning({ id: refreshTokens.id });
      await tx
        .update(refreshTokens)
        .set({ revokedAt: new Date(), replacedBy: inserted!.id })
        .where(eq(refreshTokens.id, row.id));
      const access = await tokens.issueAccessToken({
        userId: u.id,
        roles: principal.roles,
        tokenVersion: u.tokenVersion,
      });
      return { kind: 'ok' as const, access, next, principal };
    });

    if (result.kind !== 'ok') {
      metrics.authFailures.inc({ reason: `refresh_${result.kind}` });
      deleteCookie(c, REFRESH_COOKIE, { path: REFRESH_PATH });
      throw unauthorized('Refresh token rejected');
    }
    setRefreshCookie(c, result.next.token);
    return c.json(
      {
        accessToken: result.access.token,
        tokenType: 'Bearer' as const,
        expiresInSeconds: result.access.expiresIn,
        user: sessionUserOf(result.principal),
      },
      200,
    );
  });

  // ---- POST /logout ------------------------------------------------------------------------
  const logout = createRoute({
    method: 'post',
    path: '/logout',
    tags: ['auth'],
    responses: { 204: { description: 'Session revoked' } },
  });
  app.openapi(logout, async (c) => {
    assertTrustedOrigin(c);
    const raw = getCookie(c, REFRESH_COOKIE);
    if (raw && raw.length <= 128) {
      const [row] = await db
        .select({ familyId: refreshTokens.familyId, userId: refreshTokens.userId })
        .from(refreshTokens)
        .where(eq(refreshTokens.tokenHash, hashRefreshToken(raw)))
        .limit(1);
      if (row) {
        await db
          .update(refreshTokens)
          .set({ revokedAt: new Date() })
          .where(and(eq(refreshTokens.familyId, row.familyId), isNull(refreshTokens.revokedAt)));
        await audit.record({
          actorId: row.userId,
          actorLabel: row.userId,
          action: 'auth.logout',
          outcome: 'success',
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
        });
      }
    }
    deleteCookie(c, REFRESH_COOKIE, { path: REFRESH_PATH });
    return c.body(null, 204);
  });

  // ---- POST /logout-all (bumps token version: every access + refresh token dies) -----------
  const logoutAll = createRoute({
    method: 'post',
    path: '/logout-all',
    tags: ['auth'],
    middleware: [requireAuth()] as const,
    security: [{ bearerAuth: [] }],
    responses: { 204: { description: 'All sessions revoked' }, 401: errorResponses[401] },
  });
  app.openapi(logoutAll, async (c) => {
    const p = c.get('principal')!;
    await db.transaction(async (tx) => {
      await tx
        .update(users)
        .set({ tokenVersion: sql`${users.tokenVersion} + 1`, updatedAt: new Date() })
        .where(eq(users.id, p.userId));
      await tx
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.userId, p.userId), isNull(refreshTokens.revokedAt)));
      await audit.record(
        {
          actorId: p.userId,
          actorLabel: p.email,
          action: 'auth.logout_all',
          outcome: 'success',
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
        },
        tx,
      );
    });
    deleteCookie(c, REFRESH_COOKIE, { path: REFRESH_PATH });
    return c.body(null, 204);
  });

  // ---- GET /me -----------------------------------------------------------------------------
  const me = createRoute({
    method: 'get',
    path: '/me',
    tags: ['auth'],
    middleware: [requireAuth()] as const,
    security: [{ bearerAuth: [] }],
    responses: {
      200: {
        description: 'Current principal',
        content: { 'application/json': { schema: SessionUser } },
      },
      401: errorResponses[401],
    },
  });
  app.openapi(me, (c) => c.json(sessionUserOf(c.get('principal')!), 200));

  // ---- POST /password (self-service change; revokes other sessions) ------------------------
  const ChangePassword = z.strictObject({
    currentPassword: z.string().min(1).max(256),
    newPassword: z.string().min(14).max(256),
  });
  const changePassword = createRoute({
    method: 'post',
    path: '/password',
    tags: ['auth'],
    middleware: [
      requireAuth(),
      rateLimit(limiter, {
        name: 'password',
        capacity: 5,
        refillPerSecond: 5 / 60,
        keyBy: 'ip+user',
      }),
    ] as const,
    security: [{ bearerAuth: [] }],
    request: {
      body: { content: { 'application/json': { schema: ChangePassword } }, required: true },
    },
    responses: { 204: { description: 'Password changed' }, ...errorResponses },
  });
  app.openapi(changePassword, async (c) => {
    const p = c.get('principal')!;
    const { currentPassword, newPassword } = c.req.valid('json');
    const [u] = await db
      .select({ passwordHash: users.passwordHash })
      .from(users)
      .where(eq(users.id, p.userId))
      .limit(1);
    if (!u || !(await verifyPassword(u.passwordHash, currentPassword))) {
      await audit.record({
        actorId: p.userId,
        actorLabel: p.email,
        action: 'auth.password_change',
        outcome: 'denied',
        requestId: c.get('requestId'),
        sourceIp: c.get('clientIp'),
      });
      throw unauthorized('Current password is incorrect');
    }
    const newHash = await hashPassword(newPassword);
    await db.transaction(async (tx) => {
      await tx
        .update(users)
        .set({
          passwordHash: newHash,
          tokenVersion: sql`${users.tokenVersion} + 1`,
          updatedAt: new Date(),
        })
        .where(eq(users.id, p.userId));
      await tx
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.userId, p.userId), isNull(refreshTokens.revokedAt)));
      await audit.record(
        {
          actorId: p.userId,
          actorLabel: p.email,
          action: 'auth.password_change',
          outcome: 'success',
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
        },
        tx,
      );
    });
    deleteCookie(c, REFRESH_COOKIE, { path: REFRESH_PATH });
    return c.body(null, 204);
  });

  // ---- SSO (OIDC) ---------------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/providers',
      tags: ['auth'],
      responses: {
        200: {
          description: 'Which login methods this deployment offers',
          content: { 'application/json': { schema: AuthProviders } },
        },
      },
    }),
    (c) =>
      c.json(
        AuthProviders.parse({
          local: true,
          oidc: {
            enabled: oidc.enabled,
            displayName: oidc.config?.displayName ?? '',
            jitProvisioning: oidc.config?.jit ?? false,
          },
        }),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/oidc/start',
      tags: ['auth'],
      middleware: [
        rateLimit(limiter, { name: 'oidc', capacity: 20, refillPerSecond: 0.5 }),
      ] as const,
      responses: {
        200: {
          description: 'Authorization URL with PKCE; state is single-use and expires in 10 minutes',
          content: { 'application/json': { schema: OidcStartResponse } },
        },
        503: {
          description: 'SSO not configured or IdP unreachable',
          content: { 'application/json': { schema: ApiError } },
        },
        ...errorResponses,
      },
    }),
    async (c) => {
      assertTrustedOrigin(c);
      return c.json(OidcStartResponse.parse(await oidc.start()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/oidc/callback',
      tags: ['auth'],
      middleware: [
        rateLimit(limiter, { name: 'oidc', capacity: 20, refillPerSecond: 0.5 }),
      ] as const,
      request: {
        body: { content: { 'application/json': { schema: OidcCallbackRequest } }, required: true },
      },
      responses: {
        200: {
          description: 'Session issued',
          content: { 'application/json': { schema: TokenResponse } },
        },
        403: {
          description: 'Identity refused (inactive, provisioning disabled)',
          content: { 'application/json': { schema: ApiError } },
        },
        409: {
          description: 'E-mail collision with a local account',
          content: { 'application/json': { schema: ApiError } },
        },
        503: {
          description: 'SSO not configured or IdP unreachable',
          content: { 'application/json': { schema: ApiError } },
        },
        ...errorResponses,
      },
    }),
    async (c) => {
      assertTrustedOrigin(c);
      const ip = c.get('clientIp');
      const requestId = c.get('requestId');
      const { user, roles, provisioned } = await oidc.callback(c.req.valid('json'), {
        ip,
        requestId,
      });
      const [fresh] = await db
        .select({ tokenVersion: users.tokenVersion })
        .from(users)
        .where(eq(users.id, user.id))
        .limit(1);
      const tokenVersion = fresh?.tokenVersion ?? user.tokenVersion;
      const principal = await loadPrincipal(db, user.id, tokenVersion, 'login');
      if (!principal) throw unauthorized('Account unavailable');
      const { access, refresh } = await issueSession(
        user.id,
        roles,
        tokenVersion,
        randomUUID(),
        ip,
        c.req.header('user-agent') ?? null,
      );
      await audit.record({
        actorId: user.id,
        actorLabel: user.email,
        action: 'auth.oidc_login',
        outcome: 'success',
        requestId,
        sourceIp: ip,
        metadata: { provisioned, roles },
      });
      setRefreshCookie(c, refresh.token);
      return c.json(
        {
          accessToken: access.token,
          tokenType: 'Bearer' as const,
          expiresInSeconds: access.expiresIn,
          user: sessionUserOf(principal),
        },
        200,
      );
    },
  );

  return app;
}
