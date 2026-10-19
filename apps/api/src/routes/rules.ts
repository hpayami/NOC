import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, ilike, sql, type SQL } from 'drizzle-orm';
import {
  ApiError,
  CoverageQuery,
  CreateDetectionValidationRequest,
  CreateValidationScheduleRequest,
  DetectionValidation,
  UpdateValidationScheduleRequest,
  ValidationSchedule,
  ValidationListQuery,
  DetectionCoverage,
  DetectionRuleDetail,
  ImportRulesRequest,
  ImportRulesResponse,
  RuleDeploymentState,
  RuleLifecycleRequest,
  RuleLifecycleValues,
  RuleListQuery,
  RuleSourceValues,
  RuleStats,
  RuleTargetsRequest,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { detectionRules } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import { sensorSiteCondition, siteScope } from '../middleware/scope';
import type { AppEnv } from '../middleware/context';
import { RuleService, type RuleActor } from '../rules/service';
import { DetectionCoverageService } from '../rules/coverage';
import { ValidationService } from '../rules/validation';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };

export const toRule = (r: typeof detectionRules.$inferSelect) =>
  DetectionRuleDetail.parse({
    id: r.id,
    source: r.source,
    externalId: r.externalId,
    revision: r.revision,
    name: r.name,
    lifecycle: r.lifecycle,
    severity: r.severity,
    attackTechniques: r.attackTechniques,
    license: r.license,
    contentSha256: r.contentSha256,
    validatedAt: r.validatedAt?.toISOString() ?? null,
    deployedAt: r.deployedAt?.toISOString() ?? null,
    enabled: r.enabled,
    action: r.action,
    classtype: r.classtype,
    ruleSet: r.ruleSet,
    content: r.content,
    sites: r.sites,
    importedBy: r.importedBy,
    createdAt: r.createdAt.toISOString(),
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
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

export function ruleRoutes(deps: Deps) {
  const { db } = deps;
  const service = new RuleService(db, deps.audit);
  const app = new OpenAPIHono<AppEnv>();
  const actorOf = (
    c: { get: (k: 'principal') => AppEnv['Variables']['principal'] } & {
      get(k: 'requestId'): string;
      get(k: 'clientIp'): string | null;
    },
  ): RuleActor => {
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
      path: '/stats',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Registry statistics',
          content: { 'application/json': { schema: RuleStats } },
        },
        ...common,
      },
    }),
    async (c) => {
      const [tot] = await db
        .select({
          total: count(),
          enabled: sql<number>`count(*) filter (where ${detectionRules.enabled})`,
          withTechniques: sql<number>`count(*) filter (where cardinality(${detectionRules.attackTechniques}) > 0)`,
        })
        .from(detectionRules);
      const byLc = await db
        .select({ k: detectionRules.lifecycle, n: count() })
        .from(detectionRules)
        .groupBy(detectionRules.lifecycle);
      const bySrc = await db
        .select({ k: detectionRules.source, n: count() })
        .from(detectionRules)
        .groupBy(detectionRules.source);
      return c.json(
        RuleStats.parse({
          total: tot?.total ?? 0,
          byLifecycle: Object.fromEntries(
            RuleLifecycleValues.map((k) => [k, byLc.find((r) => r.k === k)?.n ?? 0]),
          ),
          bySource: Object.fromEntries(
            RuleSourceValues.map((k) => [k, bySrc.find((r) => r.k === k)?.n ?? 0]),
          ),
          enabled: Number(tot?.enabled ?? 0),
          withTechniques: Number(tot?.withTechniques ?? 0),
          generatedAt: new Date().toISOString(),
        }),
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: RuleListQuery },
      responses: {
        200: {
          description: 'Rules, newest first',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(DetectionRuleDetail),
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
      if (q.lifecycle) conds.push(eq(detectionRules.lifecycle, q.lifecycle));
      if (q.source) conds.push(eq(detectionRules.source, q.source));
      if (q.severity) conds.push(eq(detectionRules.severity, q.severity));
      if (q.q) {
        const needle = `%${escapeLike(q.q)}%`;
        conds.push(
          sql`(${ilike(detectionRules.name, needle)} or ${ilike(detectionRules.externalId, needle)})`,
        );
      }
      if (q.cursor) {
        const k = decodeCursor(q.cursor);
        conds.push(
          sql`(${detectionRules.createdAt}, ${detectionRules.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await db
        .select()
        .from(detectionRules)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(detectionRules.createdAt), desc(detectionRules.id))
        .limit(q.limit + 1);
      const page = rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(toRule),
          nextCursor: rows.length > q.limit && last ? encodeCursor(last.createdAt, last.id) : null,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/coverage',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: CoverageQuery },
      responses: {
        200: {
          description:
            'ATT&CK technique coverage: registry rules × sensors acknowledging the bundle × observed × exposed, inside the caller site scope',
          content: { 'application/json': { schema: DetectionCoverage } },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        DetectionCoverage.parse(
          await new DetectionCoverageService(deps.db, deps.audit).coverage(
            siteScope(c.get('principal')),
            c.req.valid('query').days,
          ),
        ),
        200,
      ),
  );

  const validations = new ValidationService(db, deps.audit);
  app.openapi(
    createRoute({
      method: 'get',
      path: '/validations',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: ValidationListQuery },
      responses: {
        200: {
          description:
            'Detection validations (offline sample replays), newest first, inside the caller site scope',
          content: {
            'application/json': { schema: z.object({ items: z.array(DetectionValidation) }) },
          },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        {
          items: await validations.list({
            ...c.req.valid('query'),
            sensorScope: sensorSiteCondition(siteScope(c.get('principal'))),
          }),
        },
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/validations',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: CreateDetectionValidationRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Queued for the sensor',
          content: { 'application/json': { schema: DetectionValidation } },
        },
        404: err('Rule or sensor not found'),
        409: err('Rule not deployed to that sensor, sensor not Suricata or disabled'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal')!;
      const actor = {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      };
      return c.json(await validations.create(c.req.valid('json'), actor), 201);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/validation-schedules',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description:
            'Standing validation schedules with their last verdict, inside the caller site scope',
          content: {
            'application/json': { schema: z.object({ items: z.array(ValidationSchedule) }) },
          },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        {
          items: await validations.listSchedules(
            sensorSiteCondition(siteScope(c.get('principal'))),
          ),
        },
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/validation-schedules',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: CreateValidationScheduleRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Schedule created (first validation queued now)',
          content: { 'application/json': { schema: ValidationSchedule } },
        },
        404: err('Rule or sensor not found'),
        409: err('Rule not deployed to that sensor, sensor not Suricata or disabled'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal')!;
      const actor = {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      };
      return c.json(await validations.createSchedule(c.req.valid('json'), actor), 201);
    },
  );

  app.openapi(
    createRoute({
      method: 'patch',
      path: '/validation-schedules/{id}',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        body: {
          content: { 'application/json': { schema: UpdateValidationScheduleRequest } },
          required: true,
        },
      },
      responses: {
        200: {
          description: 'Updated',
          content: { 'application/json': { schema: ValidationSchedule } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal')!;
      const actor = {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      };
      return c.json(
        await validations.updateSchedule(c.req.valid('param').id, c.req.valid('json'), actor),
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/validations/{id}',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid() }) },
      responses: {
        200: {
          description: 'Validation',
          content: { 'application/json': { schema: DetectionValidation } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        await validations.get(
          c.req.valid('param').id,
          sensorSiteCondition(siteScope(c.get('principal'))),
        ),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/deployment',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description:
            'Per enabled sensor (inside the caller site scope): expected bundle digest vs the one the sensor acknowledged',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(RuleDeploymentState) }),
            },
          },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json({ items: await service.deploymentState(siteScope(c.get('principal'))) }, 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/import',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: { content: { 'application/json': { schema: ImportRulesRequest } }, required: true },
      },
      responses: {
        200: {
          description: 'Import summary (idempotent)',
          content: { 'application/json': { schema: ImportRulesResponse } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) =>
      c.json(ImportRulesResponse.parse(await service.import(c.req.valid('json'), actorOf(c))), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid() }) },
      responses: {
        200: {
          description: 'Rule',
          content: { 'application/json': { schema: DetectionRuleDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const [r] = await db
        .select()
        .from(detectionRules)
        .where(eq(detectionRules.id, c.req.valid('param').id))
        .limit(1);
      if (!r) throw new HTTPException(404, { message: 'Rule not found' });
      return c.json(toRule(r), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/validate',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid() }) },
      responses: {
        200: {
          description: 'Validated',
          content: { 'application/json': { schema: DetectionRuleDetail } },
        },
        404: err('Not found'),
        409: err('Wrong state'),
        422: err('Validation failed'),
        ...common,
      },
    }),
    async (c) => c.json(toRule(await service.validate(c.req.valid('param').id, actorOf(c))), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/deploy',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.deploy')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid() }) },
      responses: {
        200: {
          description: 'Deployed: sensors receive it on their next bundle fetch',
          content: { 'application/json': { schema: DetectionRuleDetail } },
        },
        404: err('Not found'),
        409: err('Not validated'),
        ...common,
      },
    }),
    async (c) => c.json(toRule(await service.deploy(c.req.valid('param').id, actorOf(c))), 200),
  );

  app.openapi(
    createRoute({
      method: 'put',
      path: '/{id}/targets',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        body: { content: { 'application/json': { schema: RuleTargetsRequest } }, required: true },
      },
      responses: {
        200: {
          description: 'Targets updated (empty = every sensor of the engine)',
          content: { 'application/json': { schema: DetectionRuleDetail } },
        },
        400: err('Unknown site'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        toRule(
          await service.setTargets(c.req.valid('param').id, c.req.valid('json').sites, actorOf(c)),
        ),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/lifecycle',
      tags: ['detection-rules'],
      middleware: [requirePermission('detection_rules.change')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        body: {
          content: {
            'application/json': {
              schema: RuleLifecycleRequest,
            },
          },
          required: true,
        },
      },
      responses: {
        200: {
          description: 'Updated',
          content: { 'application/json': { schema: DetectionRuleDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) =>
      c.json(
        toRule(
          await service.setLifecycle(
            c.req.valid('param').id,
            c.req.valid('json').lifecycle,
            actorOf(c),
          ),
        ),
        200,
      ),
  );

  return app;
}
