import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { eq, type SQL } from 'drizzle-orm';
import {
  ApiError,
  AssessmentRun,
  CreateEngagementRequest,
  CreateRunRequest,
  EngagementDecisionRequest,
  EngagementListQuery,
  EngagementRecord,
  EngagementReport,
  ReportFormatQuery,
  EngagementScopeUpdateRequest,
  EngagementTransitionRequest,
  FindingListQuery,
  FindingRecord,
  FindingUpdateRequest,
  RunDetail,
  TechniqueInfo,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { AssessmentService, techniqueCatalog, type Actor } from '../assessments/service';
import { AssetService } from '../assets/service';
import { assessmentEngagements, vulnerabilityFindings } from '../db/schema';
import { forbidden, requirePermission } from '../middleware/auth';
import { findingSiteCondition, siteScope } from '../middleware/scope';
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
const okE = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: EngagementRecord } },
});
const okR = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: AssessmentRun } },
});

export function assessmentRoutes(deps: Deps) {
  const svc = new AssessmentService(
    deps.db,
    deps.audit,
    new AssetService(deps.db, deps.audit),
    deps.logger,
  );
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
      path: '/techniques',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Techniques and whether this build can execute them',
          content: { 'application/json': { schema: z.object({ items: z.array(TechniqueInfo) }) } },
        },
        ...common,
      },
    }),
    (c) => c.json({ items: techniqueCatalog() }, 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/engagements',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: EngagementListQuery },
      responses: {
        200: {
          description: 'Engagements, newest first',
          content: {
            'application/json': { schema: z.object({ items: z.array(EngagementRecord) }) },
          },
        },
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const conds: SQL[] = [];
      if (q.status) conds.push(eq(assessmentEngagements.status, q.status));
      return c.json({ items: await svc.list(conds, q.limit) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/engagements',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.plan')] as const,
      security: [{ bearerAuth: [] }],
      request: { body: json(CreateEngagementRequest) },
      responses: {
        201: okE('Draft engagement (nothing executed)'),
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.create(c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/engagements/{id}',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: { 200: okE('Engagement'), 404: err('Not found'), ...common },
    }),
    async (c) => c.json(await svc.get(c.req.valid('param').id), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/engagements/{id}/report',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, query: ReportFormatQuery },
      responses: {
        200: {
          description:
            'Engagement report (JSON, or Markdown with ?format=markdown). Limitations are part of the report.',
          content: {
            'application/json': { schema: EngagementReport },
            'text/markdown': { schema: z.string() },
          },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const report = await svc.report(c.req.valid('param').id, actor(c));
      if (c.req.valid('query').format === 'markdown') {
        c.header('content-type', 'text/markdown; charset=utf-8');
        c.header('cache-control', 'no-store');
        return c.body(svc.reportMarkdown(report), 200);
      }
      return c.json(EngagementReport.parse(report), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'put',
      path: '/engagements/{id}/scope',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.plan')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(EngagementScopeUpdateRequest) },
      responses: {
        200: okE('New scope version; re-approval required if it was approved'),
        400: err('Validation'),
        404: err('Not found'),
        409: err('Closed'),
        ...common,
      },
    }),
    async (c) => {
      const { scope, reason } = c.req.valid('json');
      return c.json(await svc.updateScope(c.req.valid('param').id, scope, reason, actor(c)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/engagements/{id}/transition',
      tags: ['assessments'],
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(EngagementTransitionRequest) },
      responses: {
        200: okE('Transitioned'),
        400: err('Validation'),
        403: err('Permission for the target state'),
        404: err('Not found'),
        409: err('Not allowed / window / scope not approved'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) => {
      if (!c.get('principal')) throw forbidden('Authentication required');
      const { to, reason } = c.req.valid('json');
      return c.json(await svc.transition(c.req.valid('param').id, to, reason, actor(c)), 200);
    },
  );

  for (const decision of ['approve', 'reject'] as const)
    app.openapi(
      createRoute({
        method: 'post',
        path: `/engagements/{id}/${decision}`,
        tags: ['assessments'],
        middleware: [requirePermission('assessments.approve')] as const,
        security: [{ bearerAuth: [] }],
        request: { params: idParam, body: json(EngagementDecisionRequest) },
        responses: {
          200: okE('Decision recorded'),
          400: err('Validation'),
          403: err('Self-approval'),
          404: err('Not found'),
          409: err('Not awaiting approval'),
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
      method: 'get',
      path: '/engagements/{id}/runs',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Runs, newest first',
          content: { 'application/json': { schema: z.object({ items: z.array(AssessmentRun) }) } },
        },
        ...common,
      },
    }),
    async (c) => c.json({ items: await svc.listRuns(c.req.valid('param').id) }, 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/engagements/{id}/runs',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.execute')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(CreateRunRequest) },
      responses: {
        201: okR('Queued (nothing sent yet)'),
        400: err('Validation'),
        404: err('Not found'),
        409: err('Engagement not active / technique not authorised or executable'),
        422: err('Worker policy refused the scope'),
        ...common,
      },
    }),
    async (c) =>
      c.json(await svc.createRun(c.req.valid('param').id, c.req.valid('json'), actor(c)), 201),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/runs/{id}',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Run with per-target decisions and findings',
          content: { 'application/json': { schema: RunDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.runDetail(c.req.valid('param').id), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/runs/{id}/execute',
      tags: ['assessments'],
      middleware: [requirePermission('assessments.execute')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: okR('Executed synchronously; see summary'),
        404: err('Not found'),
        409: err('Not queued / engagement not active / scope changed'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.executeRun(c.req.valid('param').id, actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/runs/{id}/cancel',
      tags: ['assessments'],
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: okR('Cancelled'),
        404: err('Not found'),
        409: err('Not cancellable'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal');
      // Stop conditions may be invoked by either side of the plan/approve split.
      if (
        !p ||
        !(p.permissions.has('assessments.execute') || p.permissions.has('assessments.approve'))
      )
        throw forbidden('assessments.execute or assessments.approve required');
      return c.json(await svc.cancelRun(c.req.valid('param').id, actor(c)), 200);
    },
  );

  return app;
}

export function findingRoutes(deps: Deps) {
  const svc = new AssessmentService(
    deps.db,
    deps.audit,
    new AssetService(deps.db, deps.audit),
    deps.logger,
  );
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
      path: '/',
      tags: ['findings'],
      middleware: [requirePermission('findings.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: FindingListQuery },
      responses: {
        200: {
          description: 'Findings, most recently observed first',
          content: { 'application/json': { schema: z.object({ items: z.array(FindingRecord) }) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const conds: SQL[] = [];
      const scope = findingSiteCondition(siteScope(c.get('principal')));
      if (scope) conds.push(scope);
      if (q.engagementId) conds.push(eq(vulnerabilityFindings.engagementId, q.engagementId));
      if (q.assetId) conds.push(eq(vulnerabilityFindings.assetId, q.assetId));
      if (q.status) conds.push(eq(vulnerabilityFindings.status, q.status));
      if (q.severity) conds.push(eq(vulnerabilityFindings.severity, q.severity));
      return c.json({ items: await svc.listFindings(conds, q.limit) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'patch',
      path: '/{id}',
      tags: ['findings'],
      middleware: [requirePermission('findings.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, body: json(FindingUpdateRequest) },
      responses: {
        200: { description: 'Updated', content: { 'application/json': { schema: FindingRecord } } },
        400: err('Validation'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { status, note } = c.req.valid('json');
      return c.json(await svc.updateFinding(c.req.valid('param').id, status, note, actor(c)), 200);
    },
  );

  return app;
}
