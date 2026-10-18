import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { timingSafeEqual } from 'node:crypto';
import { count, sql } from 'drizzle-orm';
import {
  ApiError,
  AssuranceStateValues,
  AuditEvent,
  AuditVerifyResponse,
  type MetricValue,
  PageQuery,
  PlatformStatus,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { alerts, assets, auditEvents, incidents, sensors } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { resolveCapabilities } from '../platform/capabilities';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});

async function dbState(
  deps: Deps,
): Promise<{ state: 'available' | 'unreachable'; migrationsApplied: number }> {
  try {
    const rows = (await deps.db.execute(
      sql`select count(*)::int as n from drizzle.__drizzle_migrations`,
    )) as unknown as Array<{ n: number }>;
    deps.metrics.dbUp.set(1);
    return { state: 'available', migrationsApplied: rows[0]?.n ?? 0 };
  } catch {
    deps.metrics.dbUp.set(0);
    return { state: 'unreachable', migrationsApplied: 0 };
  }
}

export function healthRoutes(deps: Deps) {
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/health',
      tags: ['platform'],
      responses: {
        200: {
          description: 'Process is up',
          content: {
            'application/json': {
              schema: z.object({
                status: z.literal('ok'),
                service: z.literal('noc-api'),
                version: z.string(),
              }),
            },
          },
        },
      },
    }),
    (c) =>
      c.json(
        { status: 'ok' as const, service: 'noc-api' as const, version: deps.env.APP_VERSION },
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/ready',
      tags: ['platform'],
      responses: {
        200: {
          description: 'Ready to serve',
          content: {
            'application/json': {
              schema: z.object({ status: z.literal('ready'), database: z.literal('available') }),
            },
          },
        },
        503: {
          description: 'Not ready',
          content: {
            'application/json': {
              schema: z.object({
                status: z.literal('not_ready'),
                database: z.literal('unreachable'),
              }),
            },
          },
        },
      },
    }),
    async (c) => {
      const d = await dbState(deps);
      return d.state === 'available'
        ? c.json({ status: 'ready' as const, database: 'available' as const }, 200)
        : c.json({ status: 'not_ready' as const, database: 'unreachable' as const }, 503);
    },
  );

  /** Prometheus scrape endpoint: JWT with platform.metrics.read, or the static METRICS_TOKEN. */
  app.get('/metrics', async (c) => {
    const principal = c.get('principal');
    const header = c.req.header('authorization');
    const staticOk = (() => {
      if (!deps.env.METRICS_TOKEN || !header?.startsWith('Bearer ')) return false;
      const given = Buffer.from(header.slice(7).trim());
      const expected = Buffer.from(deps.env.METRICS_TOKEN);
      return given.length === expected.length && timingSafeEqual(given, expected);
    })();
    if (!staticOk && !principal?.permissions.has('platform.metrics.read'))
      throw new HTTPException(401, { message: 'Metrics require authorization' });
    c.header('content-type', deps.metrics.registry.contentType);
    return c.body(await deps.metrics.registry.metrics());
  });

  return app;
}

export function platformRoutes(deps: Deps) {
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/status',
      tags: ['platform'],
      middleware: [requirePermission('platform.status.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Platform status',
          content: { 'application/json': { schema: PlatformStatus } },
        },
        401: err('Unauthenticated'),
        403: err('Forbidden'),
      },
    }),
    async (c) => {
      const now = new Date().toISOString();
      const database = await dbState(deps);
      const counts = async (
        table: typeof assets | typeof sensors | typeof alerts | typeof incidents,
        where?: ReturnType<typeof sql>,
      ) => {
        const [r] = await deps.db.select({ n: count() }).from(table).where(where);
        return r?.n ?? 0;
      };
      type Metric = z.infer<typeof MetricValue>;
      const pg = (id: string, value: number | null): Metric => ({
        id,
        source: 'postgres',
        sourceState: database.state,
        value,
        observedAt: now,
      });
      const pending = (id: string, source: string): Metric => ({
        id,
        source,
        sourceState: 'not_configured',
        value: null,
        observedAt: null,
      });
      const lag = (await deps.db.execute(
        sql`select max(extract(epoch from (now() - last_event_at))) as max from sensors where last_event_at is not null`,
      )) as unknown as Array<{ max: string | number | null }>;
      const rejected = (await deps.metrics.eventsRejected.get()).values.reduce(
        (a, v) => a + v.value,
        0,
      );
      const metrics: Metric[] =
        database.state === 'available'
          ? [
              pg('assets.total', await counts(assets)),
              pg(
                'assets.monitored',
                await counts(assets, sql`${assets.monitoringCoverage} = 'monitored'`),
              ),
              pg(
                'assets.coverage_incomplete',
                await counts(
                  assets,
                  sql`${assets.monitoringCoverage} in ('partial','unmonitored','unknown')`,
                ),
              ),
              pg('sensors.total', await counts(sensors)),
              pg('sensors.enabled', await counts(sensors, sql`${sensors.enabled} = true`)),
              pg(
                'alerts.critical_open',
                await counts(
                  alerts,
                  sql`${alerts.severity} = 'critical' and ${alerts.status} not in ('resolved','false_positive','suppressed')`,
                ),
              ),
              pg('incidents.open', await counts(incidents, sql`${incidents.status} <> 'closed'`)),
            ]
          : [];
      metrics.push(
        pending('sensors.healthy', 'sensor_heartbeat'),
        pending('sensors.unhealthy', 'sensor_heartbeat'),
        (() => {
          const row = lag[0];
          return row && row.max !== null
            ? ({
                id: 'events.ingest_lag_seconds',
                source: 'event_pipeline',
                sourceState: 'available',
                value: Math.round(Number(row.max)),
                observedAt: now,
              } as Metric)
            : pending('events.ingest_lag_seconds', 'event_pipeline');
        })(),
        {
          id: 'events.ingest_failures',
          source: 'event_pipeline',
          sourceState: 'available',
          value: rejected,
          observedAt: now,
        } as Metric,
        pending('network.traffic_bps', 'flow_collector'),
        pending('vulnerabilities.open', 'assessment_plane'),
        pending('response_actions.recent', 'response_plane'),
        pending('assessments.active', 'assessment_plane'),
      );
      const body = PlatformStatus.parse({
        service: 'noc-api',
        version: deps.env.APP_VERSION,
        environment: deps.env.NODE_ENV,
        demoData: false,
        database,
        capabilities: resolveCapabilities({
          suricataSensors: await deps.db
            .select({ enabled: sensors.enabled, lastEventAt: sensors.lastEventAt })
            .from(sensors)
            .where(sql`${sensors.kind} = 'suricata'`),
          now: new Date(),
        }),
        metrics,
        assuranceStates: [...AssuranceStateValues],
        generatedAt: now,
      });
      return c.json(body, 200);
    },
  );

  return app;
}

export function auditRoutes(deps: Deps) {
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['audit'],
      middleware: [requirePermission('audit.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: PageQuery },
      responses: {
        200: {
          description: 'Audit events, newest first',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(AuditEvent), nextCursor: z.string().nullable() }),
            },
          },
        },
        401: err('Unauthenticated'),
        403: err('Forbidden'),
      },
    }),
    async (c) => {
      const { limit, cursor } = c.req.valid('query');
      const before = cursor ? Number(cursor) : Number.MAX_SAFE_INTEGER;
      if (!Number.isFinite(before)) throw new HTTPException(400, { message: 'Invalid cursor' });
      const rows = await deps.db
        .select()
        .from(auditEvents)
        .where(sql`${auditEvents.seq} < ${before}`)
        .orderBy(sql`${auditEvents.seq} desc`)
        .limit(limit + 1);
      const page = rows.slice(0, limit).map((r) =>
        AuditEvent.parse({
          id: r.id,
          seq: r.seq,
          occurredAt: r.occurredAt.toISOString(),
          actorId: r.actorId,
          actorLabel: r.actorLabel,
          action: r.action,
          outcome: r.outcome,
          targetType: r.targetType,
          targetId: r.targetId,
          requestId: r.requestId,
          sourceIp: r.sourceIp,
          metadata: r.metadata ?? {},
          prevHash: r.prevHash,
          hash: r.hash,
        }),
      );
      return c.json(
        {
          items: page,
          nextCursor: rows.length > limit ? String(page[page.length - 1]!.seq) : null,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/verify',
      tags: ['audit'],
      middleware: [requirePermission('audit.verify')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Chain verification result',
          content: { 'application/json': { schema: AuditVerifyResponse } },
        },
        401: err('Unauthenticated'),
        403: err('Forbidden'),
      },
    }),
    async (c) => {
      const result = await deps.audit.verify();
      const p = c.get('principal')!;
      await deps.audit.record({
        actorId: p.userId,
        actorLabel: p.email,
        action: 'audit.verify',
        outcome: result.valid ? 'success' : 'failure',
        requestId: c.get('requestId'),
        sourceIp: c.get('clientIp'),
        metadata: { eventsChecked: result.eventsChecked, firstBrokenSeq: result.firstBrokenSeq },
      });
      return c.json(result, 200);
    },
  );

  return app;
}
