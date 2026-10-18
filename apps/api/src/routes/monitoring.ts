import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, gte, lte, sql } from 'drizzle-orm';
import {
  ApiError,
  CheckResult,
  CreateCheckRequest,
  CreateMaintenanceWindowRequest,
  IngestMetricsRequest,
  MaintenanceWindow,
  MetricPoint,
  MetricsQuery,
  MonitoringCheck,
  MonitoringOverview,
  OperationalStatusValues,
  ReportCheckResultRequest as ReportCheckResult,
  isPubliclyRoutable,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import {
  assetInterfaces,
  assetMetrics,
  assets,
  checkResults,
  maintenanceWindows,
  monitoringChecks,
  sensors,
} from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';
import { AvailabilityService, sensorState } from '../monitoring/service';
import { toSensorStatus } from './sensors';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const MAX_RANGE_MS = 7 * 24 * 3600 * 1000;

const toCheck = (c: typeof monitoringChecks.$inferSelect) =>
  MonitoringCheck.parse({
    id: c.id,
    assetId: c.assetId,
    kind: c.kind,
    target: c.target,
    port: c.port,
    intervalSeconds: c.intervalSeconds,
    timeoutMs: c.timeoutMs,
    enabled: c.enabled,
    collectorId: c.collectorId,
    lastRunAt: c.lastRunAt?.toISOString() ?? null,
    createdAt: c.createdAt.toISOString(),
  });
const toResult = (r: typeof checkResults.$inferSelect) =>
  CheckResult.parse({
    id: r.id,
    checkId: r.checkId,
    observedAt: r.observedAt.toISOString(),
    outcome: r.outcome,
    latencyMs: r.latencyMs,
    detail: r.detail,
    collectorState: r.collectorState,
  });
const toWindow = (w: typeof maintenanceWindows.$inferSelect) =>
  MaintenanceWindow.parse({
    id: w.id,
    assetId: w.assetId,
    segmentId: w.segmentId,
    startsAt: w.startsAt.toISOString(),
    endsAt: w.endsAt.toISOString(),
    reason: w.reason,
    createdBy: w.createdBy,
    createdAt: w.createdAt.toISOString(),
  });

export function monitoringRoutes(deps: Deps) {
  const { db, audit, limiter } = deps;
  const availability = new AvailabilityService(db);
  const app = new OpenAPIHono<AppEnv>();

  // ---- checks --------------------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/checks',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: z.object({ assetId: z.uuid().optional() }) },
      responses: {
        200: {
          description: 'Checks',
          content: { 'application/json': { schema: z.array(MonitoringCheck) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const { assetId } = c.req.valid('query');
      const rows = await db
        .select()
        .from(monitoringChecks)
        .where(assetId ? eq(monitoringChecks.assetId, assetId) : undefined)
        .orderBy(desc(monitoringChecks.createdAt))
        .limit(1000);
      return c.json(rows.map(toCheck), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/checks',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: { content: { 'application/json': { schema: CreateCheckRequest } }, required: true },
      },
      responses: {
        201: {
          description: 'Created',
          content: { 'application/json': { schema: MonitoringCheck } },
        },
        400: err('Validation'),
        404: err('Asset or collector not found'),
        422: err('Target not allowed'),
        ...common,
      },
    }),
    async (c) => {
      const body = c.req.valid('json');
      const p = c.get('principal')!;
      const [asset] = await db
        .select({ id: assets.id })
        .from(assets)
        .where(eq(assets.id, body.assetId))
        .limit(1);
      if (!asset) throw new HTTPException(404, { message: 'Asset not found' });
      // Scope control: a check may only probe an address the inventory already attributes to the asset.
      const ifaces = await db
        .select({ ips: assetInterfaces.ipAddresses })
        .from(assetInterfaces)
        .where(eq(assetInterfaces.assetId, body.assetId));
      const known = new Set(ifaces.flatMap((i) => i.ips));
      if (!known.has(body.target))
        throw new HTTPException(422, { message: 'Target is not an address of this asset' });
      if (isPubliclyRoutable(body.target))
        throw new HTTPException(422, {
          message: 'Public addresses are not probed by the platform',
        });
      if (body.collectorId) {
        const [s] = await db
          .select({ id: sensors.id })
          .from(sensors)
          .where(eq(sensors.id, body.collectorId))
          .limit(1);
        if (!s) throw new HTTPException(404, { message: 'Collector not found' });
      }
      const row = await db.transaction(async (tx) => {
        const [created] = await tx
          .insert(monitoringChecks)
          .values({ ...body, createdBy: p.userId })
          .returning();
        await audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'monitoring.check_create',
            outcome: 'success',
            targetType: 'asset',
            targetId: body.assetId,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: {
              checkId: created!.id,
              kind: body.kind,
              target: body.target,
              port: body.port,
              collectorId: body.collectorId,
            },
          },
          tx,
        );
        await availability.reevaluateAsset(tx, body.assetId);
        return created!;
      });
      return c.json(toCheck(row), 201);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/checks/{id}/results',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.read')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        query: z.object({ limit: z.coerce.number().int().min(1).max(500).default(100) }),
      },
      responses: {
        200: {
          description: 'Results, newest first',
          content: { 'application/json': { schema: z.array(CheckResult) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const { limit } = c.req.valid('query');
      const rows = await db
        .select()
        .from(checkResults)
        .where(eq(checkResults.checkId, id))
        .orderBy(desc(checkResults.observedAt), desc(checkResults.id))
        .limit(limit);
      return c.json(rows.map(toResult), 200);
    },
  );

  /** Collector-run checks report here; the platform never accepts external results for checks it runs itself. */
  app.openapi(
    createRoute({
      method: 'post',
      path: '/checks/{id}/results',
      tags: ['monitoring'],
      middleware: [
        requirePermission('monitoring.ingest'),
        rateLimit(limiter, {
          name: 'results',
          capacity: 1200,
          refillPerSecond: 40,
          keyBy: 'ip+user',
        }),
      ] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        body: {
          content: { 'application/json': { schema: z.array(ReportCheckResult).min(1).max(100) } },
          required: true,
        },
      },
      responses: {
        202: {
          description: 'Accepted',
          content: {
            'application/json': {
              schema: z.object({ stored: z.number().int(), operationalStatus: z.string() }),
            },
          },
        },
        400: err('Validation'),
        404: err('Not found'),
        409: err('Platform-run check'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const body = c.req.valid('json');
      const [check] = await db
        .select()
        .from(monitoringChecks)
        .where(eq(monitoringChecks.id, id))
        .limit(1);
      if (!check) throw new HTTPException(404, { message: 'Check not found' });
      if (!check.collectorId)
        throw new HTTPException(409, {
          message: 'This check is executed by the platform; external results are not accepted',
        });
      const now = new Date();
      const st = await sensorState(db, check.collectorId, now);
      const status = await db.transaction(async (tx) => {
        await tx.insert(checkResults).values(
          body.map((r) => ({
            checkId: id,
            observedAt: new Date(r.observedAt),
            outcome: r.outcome,
            latencyMs: r.latencyMs,
            detail: r.detail,
            collectorState: st?.derivedState ?? 'unknown',
          })),
        );
        await tx
          .update(monitoringChecks)
          .set({ lastRunAt: now })
          .where(eq(monitoringChecks.id, id));
        return availability.reevaluateAsset(tx, check.assetId, now);
      });
      return c.json({ stored: body.length, operationalStatus: status }, 202);
    },
  );

  // ---- maintenance windows -------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/maintenance-windows',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Windows (future and active)',
          content: { 'application/json': { schema: z.array(MaintenanceWindow) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const rows = await db
        .select()
        .from(maintenanceWindows)
        .where(gte(maintenanceWindows.endsAt, new Date()))
        .orderBy(maintenanceWindows.startsAt)
        .limit(500);
      return c.json(rows.map(toWindow), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/maintenance-windows',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: CreateMaintenanceWindowRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Created',
          content: { 'application/json': { schema: MaintenanceWindow } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const body = c.req.valid('json');
      const startsAt = new Date(body.startsAt);
      const endsAt = new Date(body.endsAt);
      if (endsAt <= startsAt)
        throw new HTTPException(400, { message: 'endsAt must be after startsAt' });
      if (endsAt.getTime() - startsAt.getTime() > 30 * 24 * 3600 * 1000)
        throw new HTTPException(400, { message: 'Windows longer than 30 days are not allowed' });
      const p = c.get('principal')!;
      const row = await db.transaction(async (tx) => {
        const [w] = await tx
          .insert(maintenanceWindows)
          .values({
            assetId: body.assetId,
            segmentId: body.segmentId,
            startsAt,
            endsAt,
            reason: body.reason,
            createdBy: p.userId,
          })
          .returning();
        await audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'monitoring.maintenance_window_create',
            outcome: 'success',
            targetType: body.assetId ? 'asset' : 'network_segment',
            targetId: body.assetId ?? body.segmentId,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: { windowId: w!.id, startsAt: body.startsAt, endsAt: body.endsAt },
          },
          tx,
        );
        if (body.assetId) await availability.reevaluateAsset(tx, body.assetId);
        else {
          const affected = await tx
            .select({ id: assets.id })
            .from(assets)
            .where(eq(assets.segmentId, body.segmentId!))
            .limit(5000);
          for (const a of affected) await availability.reevaluateAsset(tx, a.id);
        }
        return w!;
      });
      return c.json(toWindow(row), 201);
    },
  );

  // ---- overview ------------------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/overview',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'NOC overview',
          content: { 'application/json': { schema: MonitoringOverview } },
        },
        ...common,
      },
    }),
    async (c) => {
      const now = new Date();
      const byStatus = await db
        .select({ k: assets.operationalStatus, n: count() })
        .from(assets)
        .groupBy(assets.operationalStatus);
      const [tot] = await db
        .select({
          total: count(),
          enabled: sql<number>`count(*) filter (where ${monitoringChecks.enabled})`,
          platformRun: sql<number>`count(*) filter (where ${monitoringChecks.collectorId} is null)`,
        })
        .from(monitoringChecks);
      const sensorRows = await db.select().from(sensors).orderBy(sensors.name).limit(500);
      const sensorStatuses = [];
      for (const s of sensorRows) sensorStatuses.push(await toSensorStatus(db, s, now));
      const windows = await db
        .select()
        .from(maintenanceWindows)
        .where(and(lte(maintenanceWindows.startsAt, now), gte(maintenanceWindows.endsAt, now)))
        .limit(200);
      const recent = await db
        .select({
          r: checkResults,
          assetId: monitoringChecks.assetId,
          target: monitoringChecks.target,
          kind: monitoringChecks.kind,
        })
        .from(checkResults)
        .innerJoin(monitoringChecks, eq(monitoringChecks.id, checkResults.checkId))
        .orderBy(desc(checkResults.observedAt), desc(checkResults.id))
        .limit(25);
      return c.json(
        MonitoringOverview.parse({
          assetsByStatus: Object.fromEntries(
            OperationalStatusValues.map((k) => [k, byStatus.find((r) => r.k === k)?.n ?? 0]),
          ),
          checks: {
            total: tot?.total ?? 0,
            enabled: Number(tot?.enabled ?? 0),
            platformRun: Number(tot?.platformRun ?? 0),
          },
          sensors: sensorStatuses,
          activeMaintenanceWindows: windows.map(toWindow),
          recentResults: recent.map((x) => ({
            ...toResult(x.r),
            assetId: x.assetId,
            target: x.target,
            kind: x.kind,
          })),
          generatedAt: now.toISOString(),
        }),
        200,
      );
    },
  );

  return app;
}

/** Mounted under /api/v1/assets: per-asset numeric telemetry. */
export function assetMetricRoutes(deps: Deps) {
  const { db, limiter } = deps;
  const app = new OpenAPIHono<AppEnv>();
  const idParam = z.object({ id: z.uuid() });

  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/metrics',
      tags: ['monitoring'],
      middleware: [
        requirePermission('monitoring.ingest'),
        rateLimit(limiter, {
          name: 'metrics',
          capacity: 1200,
          refillPerSecond: 40,
          keyBy: 'ip+user',
        }),
      ] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        body: { content: { 'application/json': { schema: IngestMetricsRequest } }, required: true },
      },
      responses: {
        202: {
          description: 'Accepted',
          content: { 'application/json': { schema: z.object({ stored: z.number().int() }) } },
        },
        400: err('Validation'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const body = c.req.valid('json');
      const [asset] = await db
        .select({ id: assets.id })
        .from(assets)
        .where(eq(assets.id, id))
        .limit(1);
      if (!asset) throw new HTTPException(404, { message: 'Asset not found' });
      await db.insert(assetMetrics).values(
        body.points.map((pt) => ({
          assetId: id,
          metric: pt.metric,
          observedAt: new Date(pt.observedAt),
          value: pt.value,
          unit: pt.unit,
          source: body.source,
        })),
      );
      await db
        .update(assets)
        .set({
          lastSeenAt: sql`greatest(${assets.lastSeenAt}, ${new Date().toISOString()}::timestamptz)`,
        })
        .where(eq(assets.id, id));
      return c.json({ stored: body.points.length }, 202);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}/metrics',
      tags: ['monitoring'],
      middleware: [requirePermission('monitoring.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, query: MetricsQuery },
      responses: {
        200: {
          description: 'Points in range, oldest first',
          content: { 'application/json': { schema: z.array(MetricPoint) } },
        },
        400: err('Validation / range too large'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const q = c.req.valid('query');
      const from = new Date(q.from);
      const to = new Date(q.to);
      if (to <= from) throw new HTTPException(400, { message: 'to must be after from' });
      if (to.getTime() - from.getTime() > MAX_RANGE_MS)
        throw new HTTPException(400, { message: 'Range exceeds 7 days' });
      const rows = await db
        .select({
          metric: assetMetrics.metric,
          observedAt: assetMetrics.observedAt,
          value: assetMetrics.value,
          unit: assetMetrics.unit,
        })
        .from(assetMetrics)
        .where(
          and(
            eq(assetMetrics.assetId, id),
            eq(assetMetrics.metric, q.metric),
            gte(assetMetrics.observedAt, from),
            lte(assetMetrics.observedAt, to),
          ),
        )
        .orderBy(assetMetrics.observedAt)
        .limit(q.limit);
      return c.json(
        rows.map((r) => MetricPoint.parse({ ...r, observedAt: r.observedAt.toISOString() })),
        200,
      );
    },
  );

  return app;
}
