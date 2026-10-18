import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import {
  ApiError,
  CreateNotificationChannelRequest,
  NotificationChannel,
  NotificationDelivery,
  PlatformConditions,
  UpdateNotificationChannelRequest,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import type { Actor, OperationsService } from '../operations/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const idParam = z.object({ id: z.uuid() });

export function operationsRoutes(deps: Deps, svc: OperationsService) {
  const app = new OpenAPIHono<AppEnv>();
  const actor = (c: Context<AppEnv>): Actor => {
    const p = c.get('principal')!;
    return {
      userId: p.userId,
      label: p.email,
      requestId: c.get('requestId'),
      ip: c.get('clientIp'),
    };
  };

  app.openapi(
    createRoute({
      method: 'get',
      path: '/conditions',
      tags: ['operations'],
      middleware: [requirePermission('platform.status.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description:
            'Conditions an operator should act on, plus every check that ran (ok / failing / unavailable)',
          content: { 'application/json': { schema: PlatformConditions } },
        },
        ...common,
      },
    }),
    async (c) => c.json(PlatformConditions.parse(await svc.conditions()), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/channels',
      tags: ['operations'],
      middleware: [requirePermission('notifications.manage')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Notification channels (secrets never returned)',
          content: {
            'application/json': { schema: z.object({ items: z.array(NotificationChannel) }) },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json({ items: await svc.listChannels() }, 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/channels',
      tags: ['operations'],
      middleware: [requirePermission('notifications.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: CreateNotificationChannelRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Created',
          content: { 'application/json': { schema: NotificationChannel } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.createChannel(c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'patch',
      path: '/channels/{id}',
      tags: ['operations'],
      middleware: [requirePermission('notifications.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        body: {
          content: { 'application/json': { schema: UpdateNotificationChannelRequest } },
          required: true,
        },
      },
      responses: {
        200: {
          description: 'Updated',
          content: { 'application/json': { schema: NotificationChannel } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(await svc.updateChannel(c.req.valid('param').id, c.req.valid('json'), actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/channels/{id}/test',
      tags: ['operations'],
      middleware: [requirePermission('notifications.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Delivery attempt (sent or failed, with the HTTP status)',
          content: { 'application/json': { schema: NotificationDelivery } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.testChannel(c.req.valid('param').id, actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/deliveries',
      tags: ['operations'],
      middleware: [requirePermission('notifications.manage')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Most recent delivery attempts',
          content: {
            'application/json': { schema: z.object({ items: z.array(NotificationDelivery) }) },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json({ items: await svc.deliveries(100) }, 200),
  );

  return app;
}
