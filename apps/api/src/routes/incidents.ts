import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { eq, ne, sql, type SQL } from 'drizzle-orm';
import {
  ApiError,
  CreateIncidentRequest,
  IncidentDetail,
  IncidentLinkAlertsRequest,
  IncidentListQuery,
  IncidentNoteRequest,
  IncidentStats,
  IncidentSummary,
  IncidentTimelineEntry,
  IncidentTransitionRequest,
  IncidentUpdateRequest,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { incidents } from '../db/schema';
import { IncidentService, type Actor } from '../incidents/service';
import { requirePermission } from '../middleware/auth';
import { incidentSiteCondition, siteScope } from '../middleware/scope';
import type { AppEnv, Principal } from '../middleware/context';

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

const encodeCursor = (d: Date, id: string) =>
  Buffer.from(`${d.toISOString()}|${id}`).toString('base64url');
function decodeCursor(c: string): { at: Date; id: string } {
  const [iso, id] = Buffer.from(c, 'base64url').toString().split('|');
  const at = new Date(iso ?? '');
  if (!id || Number.isNaN(at.getTime()) || !/^[0-9a-f-]{36}$/.test(id))
    throw new HTTPException(400, { message: 'Invalid cursor' });
  return { at, id };
}

const actorOf = (p: Principal, requestId: string | null, ip: string | null): Actor => ({
  userId: p.userId,
  email: p.email,
  permissions: p.permissions,
  sites: siteScope(p),
  requestId,
  ip,
});

export function incidentRoutes(deps: Deps) {
  const svc = new IncidentService(deps.db, deps.audit, deps.bus);
  const app = new OpenAPIHono<AppEnv>();
  const actor = (c: Context<AppEnv>) =>
    actorOf(c.get('principal')!, c.get('requestId'), c.get('clientIp'));

  app.openapi(
    createRoute({
      method: 'get',
      path: '/stats',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Incident statistics',
          content: { 'application/json': { schema: IncidentStats } },
        },
        ...common,
      },
    }),
    async (c) => c.json(IncidentStats.parse(await svc.stats(siteScope(c.get('principal')))), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: IncidentListQuery },
      responses: {
        200: {
          description: 'Incidents, most recently opened first',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(IncidentSummary),
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
      const scope = incidentSiteCondition(siteScope(c.get('principal')));
      if (scope) conds.push(scope);
      if (q.status) conds.push(eq(incidents.status, q.status));
      if (q.open) conds.push(ne(incidents.status, 'closed'));
      if (q.severity) conds.push(eq(incidents.severity, q.severity));
      if (q.type) conds.push(eq(incidents.type, q.type));
      if (q.assigneeId) conds.push(eq(incidents.assigneeId, q.assigneeId));
      if (q.cursor) {
        const k = decodeCursor(q.cursor);
        conds.push(
          sql`(${incidents.openedAt}, ${incidents.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await svc.list(conds, q.limit + 1);
      const page = rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(({ _openedAt: _, ...i }) => i),
          nextCursor: rows.length > q.limit && last ? encodeCursor(last._openedAt, last.id) : null,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(CreateIncidentRequest) },
      responses: {
        201: {
          description: 'Created',
          content: { 'application/json': { schema: IncidentSummary } },
        },
        400: err('Validation'),
        404: err('Alert not found'),
        409: err('Alert attached elsewhere'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.create(c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Incident with alerts and timeline',
          content: { 'application/json': { schema: IncidentDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        IncidentDetail.parse(
          await svc.detail(c.req.valid('param').id, siteScope(c.get('principal'))),
        ),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'patch',
      path: '/{id}',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IncidentUpdateRequest) },
      responses: {
        200: {
          description: 'Updated',
          content: { 'application/json': { schema: IncidentSummary } },
        },
        400: err('Validation'),
        404: err('Not found'),
        409: err('Closed'),
        ...common,
      },
    }),
    async (c) =>
      c.json(await svc.update(c.req.valid('param').id, c.req.valid('json'), actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/transition',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IncidentTransitionRequest) },
      responses: {
        200: {
          description: 'Transitioned',
          content: { 'application/json': { schema: IncidentSummary } },
        },
        400: err('Validation'),
        403: err('Closing requires incidents.close'),
        404: err('Not found'),
        409: err('Transition not allowed / reason required'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) => {
      const { to, reason } = c.req.valid('json');
      return c.json(await svc.transition(c.req.valid('param').id, to, reason, actor(c)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/notes',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IncidentNoteRequest) },
      responses: {
        201: {
          description: 'Note appended',
          content: { 'application/json': { schema: IncidentTimelineEntry } },
        },
        400: err('Validation'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(await svc.addNote(c.req.valid('param').id, c.req.valid('json').note, actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/alerts',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(IncidentLinkAlertsRequest) },
      responses: {
        200: {
          description: 'Alerts attached',
          content: { 'application/json': { schema: IncidentSummary } },
        },
        400: err('Validation'),
        404: err('Not found'),
        409: err('Closed or alert attached elsewhere'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        await svc.linkAlerts(c.req.valid('param').id, c.req.valid('json').alertIds, actor(c)),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'delete',
      path: '/{id}/alerts/{alertId}',
      tags: ['incidents'],
      middleware: [requirePermission('incidents.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid(), alertId: z.uuid() }) },
      responses: {
        204: { description: 'Detached' },
        404: err('Not found'),
        409: err('Closed'),
        ...common,
      },
    }),
    async (c) => {
      const { id, alertId } = c.req.valid('param');
      await svc.unlinkAlert(id, alertId, actor(c));
      return c.body(null, 204);
    },
  );

  return app;
}
