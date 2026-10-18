import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { eq, type SQL } from 'drizzle-orm';
import {
  ApiError,
  IpsDecisionRequest,
  IpsDisableRequest,
  IpsEnableRequest,
  IpsPolicy,
  IpsPolicyListQuery,
  ProposeIpsPolicyRequest,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { ipsPolicies } from '../db/schema';
import type { IpsService, Actor } from '../ips/service';
import { forbidden, requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';

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
  content: { 'application/json': { schema: IpsPolicy } },
});

export function ipsRoutes(deps: Deps, svc: IpsService) {
  const app = new OpenAPIHono<AppEnv>();
  const actor = (c: Context<AppEnv>): Actor => {
    const p = c.get('principal')!;
    return {
      userId: p.userId,
      email: p.email,
      permissions: p.permissions,
      requestId: c.get('requestId'),
      ip: c.get('clientIp'),
    };
  };

  app.openapi(
    createRoute({
      method: 'get',
      path: '/policies',
      tags: ['ips'],
      middleware: [requirePermission('ips.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: IpsPolicyListQuery },
      responses: {
        200: {
          description: 'Policies, newest first',
          content: { 'application/json': { schema: z.object({ items: z.array(IpsPolicy) }) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const conds: SQL[] = [];
      if (q.sensorId) conds.push(eq(ipsPolicies.sensorId, q.sensorId));
      if (q.status) conds.push(eq(ipsPolicies.status, q.status));
      await svc.expireDue();
      return c.json({ items: await svc.list(conds, q.limit) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/policies',
      tags: ['ips'],
      middleware: [requirePermission('ips.propose')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(ProposeIpsPolicyRequest) },
      responses: {
        201: ok('Proposed; sensor unchanged'),
        400: err('Validation / public range'),
        404: err('Sensor or rule not found'),
        409: err('Sensor kind / rule lifecycle'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.propose(c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/policies/{id}',
      tags: ['ips'],
      middleware: [requirePermission('ips.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: { 200: ok('Policy'), 404: err('Not found'), ...common },
    }),
    async (c) => c.json(await svc.get(c.req.valid('param').id), 200),
  );

  for (const decision of ['approve', 'reject'] as const)
    app.openapi(
      createRoute({
        method: 'post',
        path: `/policies/{id}/${decision}`,
        tags: ['ips'],
        middleware: [requirePermission('ips.approve')] as const,
        security: [{ bearerAuth: [] }],
        request: { params: idParam, body: json(IpsDecisionRequest) },
        responses: {
          200: ok('Decision recorded'),
          400: err('Validation'),
          403: err('Self-approval'),
          404: err('Not found'),
          409: err('Not awaiting approval / duplicate'),
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
      path: '/policies/{id}/enable',
      tags: ['ips'],
      middleware: [requirePermission('ips.enable')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IpsEnableRequest) },
      responses: {
        200: ok('Enabled with TTL; sensor applies on next fetch'),
        403: err('Approver may not enable'),
        404: err('Not found'),
        409: err('Safety gate refused'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) =>
      c.json(
        await svc.enable(c.req.valid('param').id, c.req.valid('json').enabledForHours, actor(c)),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/policies/{id}/disable',
      tags: ['ips'],
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IpsDisableRequest) },
      responses: {
        200: ok('Disabled (kill switch)'),
        404: err('Not found'),
        409: err('Not enabled'),
        ...common,
      },
    }),
    async (c) => {
      // Kill switch: either side of the approve/enable separation may pull it, without approval.
      const p = c.get('principal');
      if (!p || !(p.permissions.has('ips.enable') || p.permissions.has('ips.approve')))
        throw forbidden('ips.enable or ips.approve required');
      return c.json(
        await svc.disable(c.req.valid('param').id, c.req.valid('json').reason, actor(c)),
        200,
      );
    },
  );

  return app;
}
