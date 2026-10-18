import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { asc, inArray } from 'drizzle-orm';
import { ApiError, CreateSiteRequest, Site } from '@noc/shared';
import type { Deps } from '../app-deps';
import { sites } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { siteScope } from '../middleware/scope';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const toSite = (s: typeof sites.$inferSelect): Site => ({
  key: s.key,
  name: s.name,
  description: s.description,
  createdAt: s.createdAt.toISOString(),
});

export function siteRoutes(deps: Deps) {
  const { db, audit } = deps;
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['sites'],
      middleware: [requirePermission('platform.status.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Sites visible to the caller',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(Site), restricted: z.boolean() }),
            },
          },
        },
        401: err('Unauthenticated'),
        403: err('Forbidden'),
      },
    }),
    async (c) => {
      const scope = siteScope(c.get('principal'));
      const rows = await db
        .select()
        .from(sites)
        .where(
          scope === null
            ? undefined
            : scope.length
              ? inArray(sites.key, [...scope])
              : inArray(sites.key, ['\u0000']),
        )
        .orderBy(asc(sites.key))
        .limit(500);
      return c.json({ items: rows.map(toSite), restricted: scope !== null }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/',
      tags: ['sites'],
      middleware: [requirePermission('network.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: { content: { 'application/json': { schema: CreateSiteRequest } }, required: true },
      },
      responses: {
        201: { description: 'Created', content: { 'application/json': { schema: Site } } },
        400: err('Validation'),
        401: err('Unauthenticated'),
        403: err('Forbidden'),
        409: err('Exists'),
      },
    }),
    async (c) => {
      const body = c.req.valid('json');
      const p = c.get('principal')!;
      const [row] = await db
        .insert(sites)
        .values({
          key: body.key,
          name: body.name,
          description: body.description ?? null,
          createdBy: p.userId,
        })
        .onConflictDoNothing()
        .returning();
      if (!row) throw new HTTPException(409, { message: 'Site key already exists' });
      await audit.record({
        actorId: p.userId,
        actorLabel: p.email,
        action: 'sites.create',
        outcome: 'success',
        targetType: 'site',
        targetId: row.key,
        requestId: c.get('requestId'),
        sourceIp: c.get('clientIp'),
        metadata: { name: body.name },
      });
      return c.json(toSite(row), 201);
    },
  );

  return app;
}
