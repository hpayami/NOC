import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { ApiError, PostureReport, ReportPeriodQuery } from '@noc/shared';
import type { Deps } from '../app-deps';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { ReportService } from '../reports/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});

export function reportRoutes(deps: Deps) {
  const svc = new ReportService(deps.db, deps.audit, deps.ml);
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/posture',
      tags: ['reports'],
      middleware: [requirePermission('platform.status.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: ReportPeriodQuery },
      responses: {
        200: {
          description:
            'Period posture report (JSON, or Markdown with ?format=markdown). Sections the reader may not see are withheld, never estimated.',
          content: {
            'application/json': { schema: PostureReport },
            'text/markdown': { schema: z.string() },
          },
        },
        401: err('Unauthenticated'),
        403: err('Forbidden'),
      },
    }),
    async (c) => {
      const p = c.get('principal')!;
      const q = c.req.valid('query');
      const report = await svc.posture(
        {
          userId: p.userId,
          label: p.email,
          permissions: p.permissions,
          sites: p.sites,
          requestId: c.get('requestId'),
          ip: c.get('clientIp'),
        },
        q.days,
      );
      if (q.format === 'markdown') {
        c.header('content-type', 'text/markdown; charset=utf-8');
        c.header('cache-control', 'no-store');
        return c.body(svc.markdown(report), 200);
      }
      return c.json(PostureReport.parse(report), 200);
    },
  );
  return app;
}
