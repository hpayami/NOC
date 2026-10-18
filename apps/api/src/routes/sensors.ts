import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { desc, eq } from 'drizzle-orm';
import {
  ApiError,
  RegisterSensorRequest,
  Sensor,
  SensorHealth,
  SensorHeartbeatRequest,
  SensorStatus,
  EnrolmentTokenResponse,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import type { Db, DbTx } from '../db/client';
import { sensorHealth, sensors } from '../db/schema';
import { AgentService } from '../agents/service';
import { AssetService } from '../assets/service';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';
import { sensorState } from '../monitoring/service';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };

export const toSensor = (s: typeof sensors.$inferSelect) =>
  Sensor.parse({
    id: s.id,
    name: s.name,
    kind: s.kind,
    mode: s.mode,
    hostAssetId: s.hostAssetId,
    site: s.site,
    monitoredSegmentIds: s.monitoredSegmentIds,
    engineVersion: s.engineVersion,
    ruleSetVersion: s.ruleSetVersion,
    enabled: s.enabled,
    inlineCapable: s.inlineCapable,
    registeredAt: s.registeredAt.toISOString(),
    lastHeartbeatAt: s.lastHeartbeatAt?.toISOString() ?? null,
  });

const toHealth = (h: typeof sensorHealth.$inferSelect) =>
  SensorHealth.parse({
    sensorId: h.sensorId,
    recordedAt: h.recordedAt.toISOString(),
    state: h.state,
    heartbeatAgeSeconds: h.heartbeatAgeSeconds,
    eventLagSeconds: h.eventLagSeconds,
    packetsCaptured: h.packetsCaptured,
    packetsDropped: h.packetsDropped,
    cpuPercent: h.cpuPercent,
    memoryPercent: h.memoryPercent,
    detail: h.detail,
  });

export async function toSensorStatus(db: Db | DbTx, s: typeof sensors.$inferSelect, now: Date) {
  const [latest] = await db
    .select()
    .from(sensorHealth)
    .where(eq(sensorHealth.sensorId, s.id))
    .orderBy(desc(sensorHealth.recordedAt))
    .limit(1);
  const st = await sensorState(db, s.id, now);
  return SensorStatus.parse({
    sensor: toSensor(s),
    derivedState: st?.derivedState ?? 'unknown',
    heartbeatAgeSeconds: st?.heartbeatAgeSeconds ?? null,
    latest: latest ? toHealth(latest) : null,
  });
}

export function sensorRoutes(deps: Deps) {
  const { db, audit, limiter } = deps;
  const app = new OpenAPIHono<AppEnv>();
  const idParam = z.object({ id: z.uuid() });

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['sensors'],
      middleware: [requirePermission('sensors.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Sensors and collectors with derived state',
          content: { 'application/json': { schema: z.array(SensorStatus) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const now = new Date();
      const rows = await db.select().from(sensors).orderBy(sensors.name).limit(500);
      const out = [];
      for (const s of rows) out.push(await toSensorStatus(db, s, now));
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/',
      tags: ['sensors'],
      middleware: [requirePermission('sensors.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: RegisterSensorRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Registered (disabled until enabled by an operator)',
          content: { 'application/json': { schema: Sensor } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const body = c.req.valid('json');
      const p = c.get('principal')!;
      const row = await db.transaction(async (tx) => {
        const [s] = await tx
          .insert(sensors)
          .values({ ...body, enabled: true })
          .returning();
        await audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'sensors.register',
            outcome: 'success',
            targetType: 'sensor',
            targetId: s!.id,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: { name: body.name, kind: body.kind, mode: body.mode },
          },
          tx,
        );
        return s!;
      });
      return c.json(toSensor(row), 201);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}/status',
      tags: ['sensors'],
      middleware: [requirePermission('sensors.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Derived status',
          content: { 'application/json': { schema: SensorStatus } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const [s] = await db.select().from(sensors).where(eq(sensors.id, id)).limit(1);
      if (!s) throw new HTTPException(404, { message: 'Sensor not found' });
      return c.json(await toSensorStatus(db, s, new Date()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}/health',
      tags: ['sensors'],
      middleware: [requirePermission('sensors.read')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        query: z.object({ limit: z.coerce.number().int().min(1).max(500).default(50) }),
      },
      responses: {
        200: {
          description: 'Health samples, newest first',
          content: { 'application/json': { schema: z.array(SensorHealth) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const { limit } = c.req.valid('query');
      const rows = await db
        .select()
        .from(sensorHealth)
        .where(eq(sensorHealth.sensorId, id))
        .orderBy(desc(sensorHealth.recordedAt))
        .limit(limit);
      return c.json(rows.map(toHealth), 200);
    },
  );

  /** Sensors/collectors report liveness and counters. Counters are stored as reported, never invented. */
  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/heartbeat',
      tags: ['sensors'],
      middleware: [
        requirePermission('monitoring.ingest'),
        rateLimit(limiter, {
          name: 'heartbeat',
          capacity: 120,
          refillPerSecond: 2,
          keyBy: 'ip+user',
        }),
      ] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        body: {
          content: { 'application/json': { schema: SensorHeartbeatRequest } },
          required: true,
        },
      },
      responses: {
        202: { description: 'Recorded', content: { 'application/json': { schema: SensorStatus } } },
        404: err('Not found'),
        409: err('Sensor disabled'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const body = c.req.valid('json');
      const now = new Date();
      const [s] = await db.select().from(sensors).where(eq(sensors.id, id)).limit(1);
      if (!s) throw new HTTPException(404, { message: 'Sensor not found' });
      if (!s.enabled) throw new HTTPException(409, { message: 'Sensor is disabled' });
      const updated = await db.transaction(async (tx) => {
        await tx.insert(sensorHealth).values({
          sensorId: id,
          recordedAt: now,
          state: body.state,
          heartbeatAgeSeconds: 0,
          eventLagSeconds: body.eventLagSeconds,
          packetsCaptured: body.packetsCaptured,
          packetsDropped: body.packetsDropped,
          cpuPercent: body.cpuPercent,
          memoryPercent: body.memoryPercent,
          detail: body.detail,
        });
        const [u] = await tx
          .update(sensors)
          .set({
            lastHeartbeatAt: now,
            engineVersion: body.engineVersion ?? s.engineVersion,
            ruleSetVersion: body.ruleSetVersion ?? s.ruleSetVersion,
          })
          .where(eq(sensors.id, id))
          .returning();
        return u!;
      });
      return c.json(await toSensorStatus(db, updated, now), 202);
    },
  );

  /** Operator mints a single-use enrolment token; the agent exchanges it for its credential. */
  app.openapi(
    createRoute({
      method: 'post',
      path: '/{id}/enrolment-token',
      tags: ['sensors'],
      middleware: [requirePermission('sensors.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        201: {
          description: 'Token (shown once)',
          content: { 'application/json': { schema: EnrolmentTokenResponse } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const p = c.get('principal')!;
      const agents = new AgentService(db, audit, new AssetService(db, audit));
      const r = await agents.createEnrolmentToken(id, {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      });
      return c.json(EnrolmentTokenResponse.parse(r), 201);
    },
  );

  return app;
}
