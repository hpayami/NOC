import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { sql } from 'drizzle-orm';
import {
  ApiError,
  ImportIndicatorsRequest,
  ImportIndicatorsResponse,
  IndicatorListQuery,
  IndicatorMatch,
  IndicatorRecord,
  ThreatIntelStats,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { threatIndicatorMatches } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { assetIdSiteCondition, siteScope } from '../middleware/scope';
import type { Actor, ThreatIntelService } from '../threat-intel/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const idParam = z.object({ id: z.uuid() });

export function threatIntelRoutes(_deps: Deps, svc: ThreatIntelService) {
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
      path: '/stats',
      tags: ['threat-intel'],
      middleware: [requirePermission('threat_intel.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Indicator counts by state, type and source; match activity',
          content: { 'application/json': { schema: ThreatIntelStats } },
        },
        ...common,
      },
    }),
    async (c) => c.json(ThreatIntelStats.parse(await svc.stats()), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/indicators',
      tags: ['threat-intel'],
      middleware: [requirePermission('threat_intel.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: IndicatorListQuery },
      responses: {
        200: {
          description:
            'Indicators (active only unless includeInactive=true), most recently matched first',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(IndicatorRecord), total: z.number().int() }),
            },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json(await svc.list(c.req.valid('query')), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/indicators/import',
      tags: ['threat-intel'],
      middleware: [requirePermission('threat_intel.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: ImportIndicatorsRequest } },
          required: true,
        },
      },
      responses: {
        200: {
          description: 'Import outcome, including retroactive matches over recent events',
          content: { 'application/json': { schema: ImportIndicatorsResponse } },
        },
        400: err('Validation'),
        422: err('Feed could not be parsed at all'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.import(c.req.valid('json'), actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/indicators/{id}/revoke',
      tags: ['threat-intel'],
      middleware: [requirePermission('threat_intel.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Revoked',
          content: { 'application/json': { schema: IndicatorRecord } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.revoke(c.req.valid('param').id, actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/matches',
      tags: ['threat-intel'],
      middleware: [requirePermission('threat_intel.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: z.object({ limit: z.coerce.number().int().min(1).max(500).default(100) }) },
      responses: {
        200: {
          description:
            'Recent indicator sightings. Site-restricted users see only matches attributed to assets in their sites',
          content: { 'application/json': { schema: z.object({ items: z.array(IndicatorMatch) }) } },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        {
          items: await svc.matches({
            limit: c.req.valid('query').limit,
            scope: assetIdSiteCondition(
              siteScope(c.get('principal')),
              sql`${threatIndicatorMatches.assetId}`,
            ),
          }),
        },
        200,
      ),
  );

  return app;
}
