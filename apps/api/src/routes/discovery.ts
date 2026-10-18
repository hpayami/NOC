import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { asc, desc, eq } from 'drizzle-orm';
import {
  ApiError,
  CreateDiscoveryJobRequest,
  DiscoveryDecisionRequest,
  DiscoveryJob,
  DiscoveryJobDetail,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { AssetService } from '../assets/service';
import { discoveryJobTargets, discoveryJobs } from '../db/schema';
import { DiscoveryService, toJob, toTarget, type Actor } from '../discovery/service';
import { requirePermission, unauthorized } from '../middleware/auth';
import type { AppEnv, Principal } from '../middleware/context';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const idParam = z.object({ id: z.uuid() });

export function discoveryRoutes(deps: Deps) {
  const { db } = deps;
  const service = new DiscoveryService(
    db,
    deps.audit,
    new AssetService(db, deps.audit),
    deps.logger,
  );
  const app = new OpenAPIHono<AppEnv>();
  const actorOf = (p: Principal | null, requestId: string, ip: string | null): Actor => {
    if (!p) throw unauthorized();
    return { userId: p.userId, label: p.email, requestId, ip };
  };

  app.openapi(
    createRoute({
      method: 'get',
      path: '/jobs',
      tags: ['discovery'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Jobs, newest first',
          content: { 'application/json': { schema: z.array(DiscoveryJob) } },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        (
          await db.select().from(discoveryJobs).orderBy(desc(discoveryJobs.createdAt)).limit(200)
        ).map(toJob),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/jobs',
      tags: ['discovery'],
      middleware: [requirePermission('discovery.run_active')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: CreateDiscoveryJobRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Requested; awaits approval',
          content: { 'application/json': { schema: DiscoveryJob } },
        },
        400: err('Validation'),
        422: err('Scope rejected by policy'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        toJob(
          await service.create(
            c.req.valid('json'),
            actorOf(c.get('principal'), c.get('requestId'), c.get('clientIp')),
          ),
        ),
        201,
      ),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/jobs/{id}',
      tags: ['discovery'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Job with per-target decisions',
          content: { 'application/json': { schema: DiscoveryJobDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const [job] = await db.select().from(discoveryJobs).where(eq(discoveryJobs.id, id)).limit(1);
      if (!job) throw new HTTPException(404, { message: 'Job not found' });
      const targets = await db
        .select()
        .from(discoveryJobTargets)
        .where(eq(discoveryJobTargets.jobId, id))
        .orderBy(asc(discoveryJobTargets.target))
        .limit(5000);
      return c.json({ job: toJob(job), targets: targets.map(toTarget) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/jobs/{id}/decision',
      tags: ['discovery'],
      middleware: [requirePermission('discovery.approve_active')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        body: {
          content: { 'application/json': { schema: DiscoveryDecisionRequest } },
          required: true,
        },
      },
      responses: {
        200: { description: 'Decided', content: { 'application/json': { schema: DiscoveryJob } } },
        400: err('Validation'),
        404: err('Not found'),
        409: err('Wrong state'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const { decision, note } = c.req.valid('json');
      return c.json(
        toJob(
          await service.decide(
            id,
            decision,
            note,
            actorOf(c.get('principal'), c.get('requestId'), c.get('clientIp')),
          ),
        ),
        200,
      );
    },
  );

  /** Claims the job and executes it in the background; progress is visible on GET /jobs/:id. */
  app.openapi(
    createRoute({
      method: 'post',
      path: '/jobs/{id}/run',
      tags: ['discovery'],
      middleware: [requirePermission('discovery.run_active')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        202: { description: 'Running', content: { 'application/json': { schema: DiscoveryJob } } },
        404: err('Not found'),
        409: err('Not approved'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const actor = actorOf(c.get('principal'), c.get('requestId'), c.get('clientIp'));
      const job = await service.claim(id, actor);
      void service
        .runJob(id, actor)
        .catch((e) => deps.logger.error({ err: e, jobId: id }, 'discovery job crashed'));
      return c.json(toJob(job), 202);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/jobs/{id}/cancel',
      tags: ['discovery'],
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Cancelled',
          content: { 'application/json': { schema: DiscoveryJob } },
        },
        404: err('Not found'),
        409: err('Wrong state'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal');
      if (!p) throw unauthorized();
      if (
        !p.permissions.has('discovery.run_active') &&
        !p.permissions.has('discovery.approve_active')
      )
        throw new HTTPException(403, {
          message: 'Missing permission: discovery.run_active or discovery.approve_active',
        });
      const { id } = c.req.valid('param');
      return c.json(
        toJob(
          await service.cancel(
            id,
            actorOf(c.get('principal'), c.get('requestId'), c.get('clientIp')),
          ),
        ),
        200,
      );
    },
  );

  return { app, service };
}
