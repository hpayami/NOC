import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { eq, gte, type SQL } from 'drizzle-orm';
import {
  ApiError,
  MlBatchScoreRequest,
  MlBatchScoreResponse,
  MlResultListQuery,
  MlScoreRecord,
  MlScoreRequest,
  MlStatus,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { mlInferenceResults } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import { mlResultSiteCondition, siteScope } from '../middleware/scope';
import type { AppEnv } from '../middleware/context';
import type { Actor } from '../ml/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const json = <T extends z.ZodType>(schema: T) => ({
  content: { 'application/json': { schema } },
  required: true,
});

export function mlRoutes(deps: Deps) {
  const svc = deps.ml;
  const app = new OpenAPIHono<AppEnv>();
  const actor = (c: Context<AppEnv>): Actor => {
    const p = c.get('principal')!;
    return {
      userId: p.userId,
      email: p.email,
      sites: siteScope(p),
      requestId: c.get('requestId'),
      ip: c.get('clientIp'),
    };
  };

  app.openapi(
    createRoute({
      method: 'get',
      path: '/status',
      tags: ['ml'],
      middleware: [requirePermission('ml.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: z.object({ fresh: z.coerce.boolean().optional() }) },
      responses: {
        200: {
          description:
            'Analysis service reachability, model register (advisory only) and stored result count',
          content: { 'application/json': { schema: MlStatus } },
        },
        ...common,
      },
    }),
    async (c) => c.json(MlStatus.parse(await svc.status(Boolean(c.req.valid('query').fresh))), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/results',
      tags: ['ml'],
      middleware: [requirePermission('ml.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: MlResultListQuery },
      responses: {
        200: {
          description: 'Stored advisory results, newest first',
          content: { 'application/json': { schema: z.object({ items: z.array(MlScoreRecord) }) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const conds: SQL[] = [];
      const scope = mlResultSiteCondition(siteScope(c.get('principal')));
      if (scope) conds.push(scope);
      if (q.subjectId) conds.push(eq(mlInferenceResults.subjectId, q.subjectId));
      if (q.minScore !== undefined) conds.push(gte(mlInferenceResults.score, q.minScore));
      return c.json({ items: await svc.list(conds, q.limit) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/score',
      tags: ['ml'],
      middleware: [requirePermission('ml.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(MlScoreRequest) },
      responses: {
        201: {
          description: 'Advisory score stored',
          content: { 'application/json': { schema: MlScoreRecord } },
        },
        404: err('Asset not found'),
        422: err('Not scorable (no events / insufficient history)'),
        502: err('Analysis service error'),
        503: err('Analysis service unreachable'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.scoreAsset(c.req.valid('json').subjectId, actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/score/batch',
      tags: ['ml'],
      middleware: [requirePermission('ml.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(MlBatchScoreRequest) },
      responses: {
        200: {
          description: 'Batch outcome with per-subject skips',
          content: { 'application/json': { schema: MlBatchScoreResponse } },
        },
        503: err('Analysis service unreachable'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.scoreBatch(c.req.valid('json').limit, actor(c)), 200),
  );

  return app;
}
