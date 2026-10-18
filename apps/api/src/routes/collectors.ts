import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { eq } from 'drizzle-orm';
import { ApiError, SnmpSnapshot, SnmpSnapshotResult } from '@noc/shared';
import type { Deps } from '../app-deps';
import { AssetService } from '../assets/service';
import { applySnmpSnapshot } from '../collectors/snmp';
import { sensors } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});

/** Push endpoints for collectors. The management plane never polls devices itself. */
export function collectorRoutes(deps: Deps) {
  const { db, limiter } = deps;
  const assetsSvc = new AssetService(db, deps.audit);
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'post',
      path: '/snmp/snapshots',
      tags: ['collectors'],
      middleware: [
        requirePermission('monitoring.ingest'),
        rateLimit(limiter, { name: 'snmp', capacity: 300, refillPerSecond: 10, keyBy: 'ip+user' }),
      ] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: { content: { 'application/json': { schema: SnmpSnapshot } }, required: true },
      },
      responses: {
        202: {
          description: 'Snapshot applied',
          content: { 'application/json': { schema: SnmpSnapshotResult } },
        },
        400: err('Validation'),
        401: err('Unauthenticated'),
        403: err('Forbidden'),
        404: err('Collector not found'),
        409: err('Collector disabled'),
      },
    }),
    async (c) => {
      const snap = c.req.valid('json');
      const p = c.get('principal')!;
      const [collector] = await db
        .select({ id: sensors.id, enabled: sensors.enabled })
        .from(sensors)
        .where(eq(sensors.id, snap.collectorId))
        .limit(1);
      if (!collector) throw new HTTPException(404, { message: 'Collector not found' });
      if (!collector.enabled) throw new HTTPException(409, { message: 'Collector is disabled' });
      const result = await applySnmpSnapshot(db, assetsSvc, snap, {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      });
      return c.json(SnmpSnapshotResult.parse(result), 202);
    },
  );

  return app;
}
