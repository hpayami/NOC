import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import {
  ApiError,
  RetentionDataClass,
  RetentionPolicy,
  RetentionPolicyUpdate,
  RetentionRunReport,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { RetentionError, type RetentionService } from '../retention/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };

const actorOf = (c: Context<AppEnv>) => {
  const p = c.get('principal')!;
  return { userId: p.userId, email: p.email, requestId: c.get('requestId'), ip: c.get('clientIp') };
};

export function retentionRoutes(deps: Deps, svc: RetentionService) {
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['retention'],
      middleware: [requirePermission('retention.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description:
            'Retention policies per data class and the last enforcement run (this process)',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(RetentionPolicy),
                lastRun: RetentionRunReport.nullable(),
              }),
            },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json({ items: await svc.list(), lastRun: svc.lastRun }, 200),
  );

  app.openapi(
    createRoute({
      method: 'put',
      path: '/{dataClass}',
      tags: ['retention'],
      middleware: [requirePermission('retention.modify')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ dataClass: RetentionDataClass }),
        body: {
          content: { 'application/json': { schema: RetentionPolicyUpdate } },
          required: true,
        },
      },
      responses: {
        200: {
          description: 'Updated',
          content: { 'application/json': { schema: RetentionPolicy } },
        },
        400: err('Validation / below floor'),
        ...common,
      },
    }),
    async (c) => {
      try {
        return c.json(
          await svc.update(c.req.valid('param').dataClass, c.req.valid('json'), actorOf(c)),
          200,
        );
      } catch (e) {
        if (e instanceof RetentionError) throw new HTTPException(400, { message: e.message });
        throw e;
      }
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/run',
      tags: ['retention'],
      middleware: [requirePermission('retention.modify')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Enforcement report',
          content: { 'application/json': { schema: RetentionRunReport } },
        },
        ...common,
      },
    }),
    async (c) => c.json(await svc.run('manual', actorOf(c)), 200),
  );

  return app;
}
