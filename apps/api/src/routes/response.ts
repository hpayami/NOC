import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { eq, sql, type SQL } from 'drizzle-orm';
import {
  ApiError,
  ProposeResponseActionRequest,
  ResponseActionListQuery,
  ResponseActionRecord,
  ResponseDecisionRequest,
  ResponseExecutionRequest,
  ResponseExecutorInfo,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { responseActions } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import { responseActionSiteCondition, siteScope } from '../middleware/scope';
import type { AppEnv } from '../middleware/context';
import { ResponseActionService, executorCatalog, type Actor } from '../response/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const idParam = z.object({ id: z.uuid() });
const json = <T extends z.ZodType>(schema: T) => ({
  content: { 'application/json': { schema } },
  required: true,
});
const ok = (description: string) => ({
  description,
  content: { 'application/json': { schema: ResponseActionRecord } },
});

const encodeCursor = (d: Date, id: string) =>
  Buffer.from(`${d.toISOString()}|${id}`).toString('base64url');
function decodeCursor(c: string): { at: Date; id: string } {
  const [iso, id] = Buffer.from(c, 'base64url').toString().split('|');
  const at = new Date(iso ?? '');
  if (!id || Number.isNaN(at.getTime()) || !/^[0-9a-f-]{36}$/.test(id))
    throw new HTTPException(400, { message: 'Invalid cursor' });
  return { at, id };
}

export function responseRoutes(deps: Deps) {
  const svc = new ResponseActionService(deps.db, deps.audit);
  const app = new OpenAPIHono<AppEnv>();
  const actor = (c: Context<AppEnv>): Actor => {
    const p = c.get('principal')!;
    return {
      userId: p.userId,
      email: p.email,
      permissions: p.permissions,
      sites: siteScope(p),
      requestId: c.get('requestId'),
      ip: c.get('clientIp'),
    };
  };

  app.openapi(
    createRoute({
      method: 'get',
      path: '/executors',
      tags: ['response'],
      middleware: [requirePermission('response.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Which action kinds this build can execute, and the approvals each needs',
          content: {
            'application/json': { schema: z.object({ items: z.array(ResponseExecutorInfo) }) },
          },
        },
        ...common,
      },
    }),
    (c) => c.json({ items: executorCatalog() }, 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['response'],
      middleware: [requirePermission('response.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: ResponseActionListQuery },
      responses: {
        200: {
          description: 'Response actions, newest first',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(ResponseActionRecord),
                nextCursor: z.string().nullable(),
              }),
            },
          },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const conds: SQL[] = [];
      const scope = responseActionSiteCondition(siteScope(c.get('principal')));
      if (scope) conds.push(scope);
      if (q.incidentId) conds.push(eq(responseActions.incidentId, q.incidentId));
      if (q.status) conds.push(eq(responseActions.status, q.status));
      if (q.kind) conds.push(eq(responseActions.kind, q.kind));
      if (q.cursor) {
        const k = decodeCursor(q.cursor);
        conds.push(
          sql`(${responseActions.createdAt}, ${responseActions.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await svc.list(conds, q.limit + 1);
      const page = rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(({ _createdAt: _, ...r }) => r),
          nextCursor: rows.length > q.limit && last ? encodeCursor(last._createdAt, last.id) : null,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/',
      tags: ['response'],
      middleware: [requirePermission('response.propose')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(ProposeResponseActionRequest) },
      responses: {
        201: ok('Proposed (nothing executed)'),
        400: err('Validation'),
        404: err('Target or incident not found'),
        409: err('Incident closed'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.propose(c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}',
      tags: ['response'],
      middleware: [requirePermission('response.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: ok('Response action with approvals and result'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.get(c.req.valid('param').id, siteScope(c.get('principal'))), 200),
  );

  for (const decision of ['approve', 'reject'] as const)
    app.openapi(
      createRoute({
        method: 'post',
        path: `/{id}/${decision}`,
        tags: ['response'],
        middleware: [requirePermission('response.approve')] as const,
        security: [{ bearerAuth: [] }],
        request: { params: idParam, body: json(ResponseDecisionRequest) },
        responses: {
          200: ok(decision === 'approve' ? 'Approval recorded' : 'Rejected'),
          400: err('Validation'),
          403: err('Self-approval / missing permission'),
          404: err('Not found'),
          409: err('Not awaiting approval / expired / duplicate'),
          401: err('Unauthenticated'),
        },
      }),
      async (c) =>
        c.json(
          await svc.decide(
            c.req.valid('param').id,
            decision === 'approve' ? 'approved' : 'rejected',
            c.req.valid('json').justification,
            actor(c),
          ),
          200,
        ),
    );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/execute',
      tags: ['response'],
      middleware: [requirePermission('response.execute')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(ResponseExecutionRequest) },
      responses: {
        200: ok('Executed'),
        403: err('Separation of duties / missing permission'),
        404: err('Not found'),
        409: err('Not approved / expired / executor unavailable'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) =>
      c.json(await svc.execute(c.req.valid('param').id, c.req.valid('json').note, actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/rollback',
      tags: ['response'],
      middleware: [requirePermission('response.rollback')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(ResponseExecutionRequest) },
      responses: {
        200: ok('Rolled back'),
        404: err('Not found'),
        409: err('Not executed'),
        ...common,
      },
    }),
    async (c) =>
      c.json(await svc.rollback(c.req.valid('param').id, c.req.valid('json').note, actor(c)), 200),
  );

  return app;
}
