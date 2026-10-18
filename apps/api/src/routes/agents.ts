import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { eq } from 'drizzle-orm';
import {
  AgentEnrolRequest,
  AgentEnrolResponse,
  AgentInventory,
  ApiError,
  IngestMetricsRequest,
  IpsAckRequest,
  NeighborBatch,
  SensorIpsDirective,
  NeighborBatchResult,
  SensorHeartbeatRequest,
} from '@noc/shared';
import { AgentService } from '../agents/service';
import type { Deps } from '../app-deps';
import { AssetService } from '../assets/service';
import { assetMetrics, assets } from '../db/schema';
import { requireSensor } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const sensorAuth = [{ sensorCredential: [] }];

/**
 * Endpoints for host agents authenticated with their sensor credential (`X-Sensor-Credential`).
 * No user JWT is accepted here and sensor credentials are not accepted anywhere else.
 */
export function agentRoutes(deps: Deps) {
  const { db, limiter } = deps;
  const service = new AgentService(db, deps.audit, new AssetService(db, deps.audit));
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'post',
      path: '/enrol',
      tags: ['agents'],
      middleware: [
        rateLimit(limiter, { name: 'enrol', capacity: 10, refillPerSecond: 10 / 60 }),
      ] as const,
      request: {
        body: { content: { 'application/json': { schema: AgentEnrolRequest } }, required: true },
      },
      responses: {
        201: {
          description: 'Enrolled; credential shown once',
          content: { 'application/json': { schema: AgentEnrolResponse } },
        },
        400: err('Validation'),
        401: err('Enrolment rejected'),
        429: err('Rate limited'),
      },
    }),
    async (c) =>
      c.json(
        AgentEnrolResponse.parse(
          await service.enrol(c.req.valid('json'), c.get('clientIp'), c.get('requestId')),
        ),
        201,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/heartbeat',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, { name: 'agent-hb', capacity: 60, refillPerSecond: 1, keyBy: 'sensor' }),
      ] as const,
      security: sensorAuth,
      request: {
        body: {
          content: { 'application/json': { schema: SensorHeartbeatRequest } },
          required: true,
        },
      },
      responses: {
        204: { description: 'Recorded' },
        401: err('Unauthenticated'),
        429: err('Rate limited'),
      },
    }),
    async (c) => {
      const sensor = c.get('sensor')!;
      await service.heartbeat(sensor, c.req.valid('json'));
      // A heartbeat that no longer qualifies the sensor (degraded, lost inline capability) ends
      // inline prevention right here, before the sensor's next directive fetch.
      await deps.ips.enforceSensorHealth(new Date(), sensor.sensorId);
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/inventory',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, {
          name: 'agent-inv',
          capacity: 30,
          refillPerSecond: 0.1,
          keyBy: 'sensor',
        }),
      ] as const,
      security: sensorAuth,
      request: {
        body: { content: { 'application/json': { schema: AgentInventory } }, required: true },
      },
      responses: {
        202: {
          description: 'Applied',
          content: {
            'application/json': {
              schema: z.object({
                assetId: z.uuid().nullable(),
                decision: z.enum(['match', 'create', 'ambiguous']),
                services: z.number().int(),
              }),
            },
          },
        },
        400: err('Validation'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) =>
      c.json(
        await service.applyInventory(
          c.get('sensor')!,
          c.req.valid('json'),
          c.get('clientIp'),
          c.get('requestId'),
        ),
        202,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/metrics',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, {
          name: 'agent-metrics',
          capacity: 600,
          refillPerSecond: 10,
          keyBy: 'sensor',
        }),
      ] as const,
      security: sensorAuth,
      request: {
        body: { content: { 'application/json': { schema: IngestMetricsRequest } }, required: true },
      },
      responses: {
        202: {
          description: 'Stored',
          content: { 'application/json': { schema: z.object({ stored: z.number().int() }) } },
        },
        400: err('Validation'),
        401: err('Unauthenticated'),
        409: err('Agent has no host asset yet (send inventory first)'),
      },
    }),
    async (c) => {
      const sensor = c.get('sensor')!;
      if (!sensor.hostAssetId)
        throw new HTTPException(409, { message: 'Send an inventory before metrics' });
      const body = c.req.valid('json');
      await db.insert(assetMetrics).values(
        body.points.map((pt) => ({
          assetId: sensor.hostAssetId!,
          metric: pt.metric,
          observedAt: new Date(pt.observedAt),
          value: pt.value,
          unit: pt.unit,
          source: `agent:${sensor.sensorId}`,
        })),
      );
      await db
        .update(assets)
        .set({ lastSeenAt: new Date() })
        .where(eq(assets.id, sensor.hostAssetId));
      return c.json({ stored: body.points.length }, 202);
    },
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/neighbors',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, {
          name: 'agent-neigh',
          capacity: 120,
          refillPerSecond: 2,
          keyBy: 'sensor',
        }),
      ] as const,
      security: sensorAuth,
      request: {
        body: { content: { 'application/json': { schema: NeighborBatch } }, required: true },
      },
      responses: {
        202: {
          description: 'Processed',
          content: { 'application/json': { schema: NeighborBatchResult } },
        },
        400: err('Validation'),
        401: err('Unauthenticated'),
      },
    }),
    async (c) => {
      const sensor = c.get('sensor')!;
      const r = await service.applyNeighbors(c.req.valid('json'), `agent:${sensor.sensorId}`, {
        userId: null,
        label: `agent:${sensor.name}`,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      });
      return c.json(r, 202);
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/ips-directive',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, {
          name: 'agent-ips',
          capacity: 60,
          refillPerSecond: 1,
          keyBy: 'sensor',
        }),
      ] as const,
      security: sensorAuth,
      responses: {
        200: {
          description:
            'The inline-prevention directive this sensor must run now. Defaults to detect-only; always fail-open.',
          content: { 'application/json': { schema: SensorIpsDirective } },
        },
        401: err('Unauthenticated'),
      },
    }),
    async (c) => c.json(await deps.ips.directiveFor(c.get('sensor')!.sensorId), 200),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/ips-ack',
      tags: ['agents'],
      middleware: [
        requireSensor(),
        rateLimit(limiter, {
          name: 'agent-ips',
          capacity: 60,
          refillPerSecond: 1,
          keyBy: 'sensor',
        }),
      ] as const,
      security: sensorAuth,
      request: {
        body: { content: { 'application/json': { schema: IpsAckRequest } }, required: true },
      },
      responses: { 204: { description: 'Recorded' }, 401: err('Unauthenticated') },
    }),
    async (c) => {
      await deps.ips.ack(c.get('sensor')!.sensorId, c.req.valid('json'));
      return c.body(null, 204);
    },
  );

  return { app, service };
}
