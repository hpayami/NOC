import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { and, eq, gt, inArray, isNull, sql } from 'drizzle-orm';
import {
  ApiError,
  CreateUserRequest,
  PageQuery,
  ROLE_DEFINITIONS,
  ROLE_KEYS,
  Role,
  RoleKeySchema,
  User,
  UserListResponse,
  UserStatus,
  type RoleKey,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { refreshTokens, userRoles, users } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { hashPassword } from '../security/password';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});

export function userRoutes(deps: Deps) {
  const { db, audit } = deps;
  const app = new OpenAPIHono<AppEnv>();

  async function toPublic(ids: string[]) {
    if (ids.length === 0) return [];
    const rows = await db.select().from(users).where(inArray(users.id, ids));
    const roleRows = await db.select().from(userRoles).where(inArray(userRoles.userId, ids));
    return rows.map((u) =>
      User.parse({
        id: u.id,
        email: u.email,
        displayName: u.displayName,
        status: u.status,
        roles: roleRows.filter((r) => r.userId === u.id).map((r) => r.roleKey),
        mfaEnrolled: u.mfaEnrolled,
        authProvider: u.authProvider,
        lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
        createdAt: u.createdAt.toISOString(),
      }),
    );
  }

  const list = createRoute({
    method: 'get',
    path: '/',
    tags: ['users'],
    middleware: [requirePermission('users.read')] as const,
    security: [{ bearerAuth: [] }],
    request: { query: PageQuery },
    responses: {
      200: { description: 'Users', content: { 'application/json': { schema: UserListResponse } } },
      401: err('Unauthenticated'),
      403: err('Forbidden'),
    },
  });
  app.openapi(list, async (c) => {
    const { limit, cursor } = c.req.valid('query');
    const rows = await db
      .select({ id: users.id, createdAt: users.createdAt })
      .from(users)
      .where(cursor ? gt(users.createdAt, new Date(cursor)) : undefined)
      .orderBy(users.createdAt)
      .limit(limit + 1);
    const page = rows.slice(0, limit);
    const items = (await toPublic(page.map((r) => r.id))).sort((a, b) =>
      a.createdAt.localeCompare(b.createdAt),
    );
    return c.json(
      {
        items,
        nextCursor: rows.length > limit ? page[page.length - 1]!.createdAt.toISOString() : null,
      },
      200,
    );
  });

  const create = createRoute({
    method: 'post',
    path: '/',
    tags: ['users'],
    middleware: [requirePermission('users.manage', 'users.assign_roles')] as const,
    security: [{ bearerAuth: [] }],
    request: {
      body: { content: { 'application/json': { schema: CreateUserRequest } }, required: true },
    },
    responses: {
      201: { description: 'Created', content: { 'application/json': { schema: User } } },
      400: err('Validation'),
      401: err('Unauthenticated'),
      403: err('Forbidden'),
      409: err('Email already exists'),
    },
  });
  app.openapi(create, async (c) => {
    const body = c.req.valid('json');
    const actor = c.get('principal')!;
    const passwordHash = await hashPassword(body.password);
    const created = await db.transaction(async (tx) => {
      const [existing] = await tx
        .select({ id: users.id })
        .from(users)
        .where(sql`lower(${users.email}) = lower(${body.email})`)
        .limit(1);
      if (existing) throw new HTTPException(409, { message: 'Email already exists' });
      const [u] = await tx
        .insert(users)
        .values({ email: body.email.toLowerCase(), displayName: body.displayName, passwordHash })
        .returning({ id: users.id });
      if (body.roles.length > 0)
        await tx
          .insert(userRoles)
          .values(
            body.roles.map((roleKey) => ({ userId: u!.id, roleKey, grantedBy: actor.userId })),
          );
      await audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.email,
          action: 'users.create',
          outcome: 'success',
          targetType: 'user',
          targetId: u!.id,
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
          metadata: { roles: body.roles },
        },
        tx,
      );
      return u!.id;
    });
    const [pub] = await toPublic([created]);
    return c.json(pub!, 201);
  });

  const setRoles = createRoute({
    method: 'put',
    path: '/{id}/roles',
    tags: ['users'],
    middleware: [requirePermission('users.assign_roles')] as const,
    security: [{ bearerAuth: [] }],
    request: {
      params: z.object({ id: z.uuid() }),
      body: {
        content: {
          'application/json': {
            schema: z.strictObject({ roles: z.array(RoleKeySchema).max(ROLE_KEYS.length) }),
          },
        },
        required: true,
      },
    },
    responses: {
      200: { description: 'Updated', content: { 'application/json': { schema: User } } },
      400: err('Validation'),
      401: err('Unauthenticated'),
      403: err('Forbidden'),
      404: err('Not found'),
    },
  });
  app.openapi(setRoles, async (c) => {
    const { id } = c.req.valid('param');
    const { roles } = c.req.valid('json');
    const actor = c.get('principal')!;
    if (id === actor.userId)
      throw new HTTPException(403, { message: 'Cannot change your own roles' });
    await db.transaction(async (tx) => {
      const [u] = await tx.select({ id: users.id }).from(users).where(eq(users.id, id)).limit(1);
      if (!u) throw new HTTPException(404, { message: 'User not found' });
      await tx.delete(userRoles).where(eq(userRoles.userId, id));
      if (roles.length > 0)
        await tx.insert(userRoles).values(
          [...new Set<RoleKey>(roles)].map((roleKey) => ({
            userId: id,
            roleKey,
            grantedBy: actor.userId,
          })),
        );
      // Role changes take effect immediately: invalidate outstanding tokens.
      await tx
        .update(users)
        .set({ tokenVersion: sql`${users.tokenVersion} + 1`, updatedAt: new Date() })
        .where(eq(users.id, id));
      await tx
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.userId, id), isNull(refreshTokens.revokedAt)));
      await audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.email,
          action: 'users.set_roles',
          outcome: 'success',
          targetType: 'user',
          targetId: id,
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
          metadata: { roles },
        },
        tx,
      );
    });
    const [pub] = await toPublic([id]);
    return c.json(pub!, 200);
  });

  const setStatus = createRoute({
    method: 'put',
    path: '/{id}/status',
    tags: ['users'],
    middleware: [requirePermission('users.manage')] as const,
    security: [{ bearerAuth: [] }],
    request: {
      params: z.object({ id: z.uuid() }),
      body: {
        content: { 'application/json': { schema: z.strictObject({ status: UserStatus }) } },
        required: true,
      },
    },
    responses: {
      200: { description: 'Updated', content: { 'application/json': { schema: User } } },
      400: err('Validation'),
      401: err('Unauthenticated'),
      403: err('Forbidden'),
      404: err('Not found'),
    },
  });
  app.openapi(setStatus, async (c) => {
    const { id } = c.req.valid('param');
    const { status } = c.req.valid('json');
    const actor = c.get('principal')!;
    if (id === actor.userId)
      throw new HTTPException(403, { message: 'Cannot change your own status' });
    await db.transaction(async (tx) => {
      const [u] = await tx
        .update(users)
        .set({
          status,
          lockedUntil: null,
          failedLoginCount: 0,
          tokenVersion: sql`${users.tokenVersion} + 1`,
          updatedAt: new Date(),
        })
        .where(eq(users.id, id))
        .returning({ id: users.id });
      if (!u) throw new HTTPException(404, { message: 'User not found' });
      if (status !== 'active')
        await tx
          .update(refreshTokens)
          .set({ revokedAt: new Date() })
          .where(and(eq(refreshTokens.userId, id), isNull(refreshTokens.revokedAt)));
      await audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.email,
          action: 'users.set_status',
          outcome: 'success',
          targetType: 'user',
          targetId: id,
          requestId: c.get('requestId'),
          sourceIp: c.get('clientIp'),
          metadata: { status },
        },
        tx,
      );
    });
    const [pub] = await toPublic([id]);
    return c.json(pub!, 200);
  });

  return app;
}

export function roleRoutes() {
  const app = new OpenAPIHono<AppEnv>();
  const list = createRoute({
    method: 'get',
    path: '/',
    tags: ['users'],
    middleware: [requirePermission('roles.read')] as const,
    security: [{ bearerAuth: [] }],
    responses: {
      200: { description: 'Roles', content: { 'application/json': { schema: z.array(Role) } } },
      401: err('Unauthenticated'),
      403: err('Forbidden'),
    },
  });
  app.openapi(list, (c) =>
    c.json(
      ROLE_KEYS.map((key) =>
        Role.parse({
          key,
          ...ROLE_DEFINITIONS[key],
          permissions: [...ROLE_DEFINITIONS[key].permissions],
        }),
      ),
      200,
    ),
  );
  return app;
}
