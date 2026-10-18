import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import type { Context } from 'hono';
import {
  ApiError,
  CveId,
  ImportVulnerabilitiesRequest,
  ImportVulnerabilitiesResponse,
  VulnerabilityCatalogStats,
  VulnerabilityListQuery,
  VulnerabilityRecord,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { VulnerabilityService, type Actor } from '../vulnerabilities/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };

export function vulnerabilityRoutes(deps: Deps) {
  const svc = new VulnerabilityService(deps.db, deps.audit);
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
      tags: ['vulnerabilities'],
      middleware: [requirePermission('findings.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description:
            'Catalogue size, known-exploited count, last import; plus CVEs referenced by findings but not catalogued',
          content: {
            'application/json': {
              schema: VulnerabilityCatalogStats.extend({ uncatalogued: z.array(z.string()) }),
            },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json({ ...(await svc.stats()), uncatalogued: await svc.uncatalogued() }, 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['vulnerabilities'],
      middleware: [requirePermission('findings.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: VulnerabilityListQuery },
      responses: {
        200: {
          description: 'Catalogue entries, known-exploited and highest CVSS first',
          content: {
            'application/json': { schema: z.object({ items: z.array(VulnerabilityRecord) }) },
          },
        },
        ...common,
      },
    }),
    async (c) => c.json({ items: await svc.list(c.req.valid('query')) }, 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/import',
      tags: ['vulnerabilities'],
      middleware: [requirePermission('threat_intel.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: ImportVulnerabilitiesRequest } },
          required: true,
        },
      },
      responses: {
        200: {
          description:
            'Import report; findings referencing imported CVEs get CVSS filled in where missing',
          content: { 'application/json': { schema: ImportVulnerabilitiesResponse } },
        },
        422: err('Feed rejected'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.import(c.req.valid('json'), actor(c)), 200),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{cveId}',
      tags: ['vulnerabilities'],
      middleware: [requirePermission('findings.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ cveId: CveId }) },
      responses: {
        200: {
          description: 'Catalogue entry',
          content: { 'application/json': { schema: VulnerabilityRecord } },
        },
        404: err('Not in the catalogue'),
        ...common,
      },
    }),
    async (c) => c.json(await svc.get(c.req.valid('param').cveId), 200),
  );

  return app;
}
