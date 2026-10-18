import { OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { eq } from 'drizzle-orm';
import { IngestReport } from '@noc/shared';
import type { Deps } from '../app-deps';
import { sensors } from '../db/schema';
import { EventPipeline, type IngestSource } from '../events/pipeline';
import { unauthorized } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';

/**
 * Engine telemetry ingestion. Two callers are accepted:
 *  - a sensor presenting its credential (the normal path; its identity is the sensor itself);
 *  - a user holding `events.ingest` with `?sensorId=` for replaying fixtures/PCAP-derived EVE
 *    into a registered sensor (detection testing). Everything else is refused.
 * Bodies are NDJSON (`application/x-ndjson`) or a JSON array; at most 1000 records per call.
 */
export function ingestRoutes(deps: Deps) {
  const { db, limiter } = deps;
  const pipeline = new EventPipeline(db, deps.metrics, deps.bus, deps.threatIntel);
  const app = new OpenAPIHono<AppEnv>();

  const resolveSource = async (c: Context<AppEnv>, expectedKind: string): Promise<IngestSource> => {
    const sensor = c.get('sensor');
    const principal = c.get('principal');
    let source: IngestSource;
    if (sensor) {
      source = { sensorId: sensor.sensorId, sensorName: sensor.name, kind: sensor.kind };
    } else if (principal?.permissions.has('events.ingest')) {
      const sensorId = c.req.query('sensorId') ?? '';
      if (!/^[0-9a-f-]{36}$/.test(sensorId))
        throw new HTTPException(400, {
          message: 'sensorId query parameter is required for replay',
        });
      const [s] = await db
        .select({
          id: sensors.id,
          name: sensors.name,
          kind: sensors.kind,
          enabled: sensors.enabled,
        })
        .from(sensors)
        .where(eq(sensors.id, sensorId))
        .limit(1);
      if (!s) throw new HTTPException(404, { message: 'Sensor not found' });
      if (!s.enabled) throw new HTTPException(409, { message: 'Sensor is disabled' });
      source = { sensorId: s.id, sensorName: s.name, kind: s.kind };
      await deps.audit.record({
        actorId: principal.userId,
        actorLabel: principal.email,
        action: 'events.replay',
        outcome: 'success',
        targetType: 'sensor',
        targetId: s.id,
        requestId: c.get('requestId'),
        sourceIp: c.get('clientIp'),
        metadata: { bytes: Number(c.req.header('content-length') ?? 0), path: c.req.path },
      });
    } else {
      throw unauthorized('Sensor credential or events.ingest permission required');
    }
    if (source.kind !== expectedKind)
      throw new HTTPException(409, {
        message: `Sensor kind "${source.kind}" does not emit ${expectedKind} logs`,
      });
    return source;
  };

  app.post(
    '/zeek/logs',
    rateLimit(limiter, { name: 'zeek', capacity: 300, refillPerSecond: 5, keyBy: 'sensor' }),
    async (c) => {
      const source = await resolveSource(c, 'zeek');
      const defaultPath = c.req.query('path');
      const report = await pipeline.ingestZeek(await c.req.text(), source, defaultPath);
      c.get('log').info(
        { sensor: source.sensorName, ...report, rejections: undefined },
        'zeek ingest',
      );
      return c.json(IngestReport.parse(report), 202);
    },
  );

  app.post(
    '/suricata/eve',
    rateLimit(limiter, { name: 'eve', capacity: 300, refillPerSecond: 5, keyBy: 'sensor' }),
    async (c) => {
      const source = await resolveSource(c, 'suricata');
      const body = await c.req.text();
      const report = await pipeline.ingestEve(body, source);
      c.get('log').info(
        { sensor: source.sensorName, ...report, rejections: undefined },
        'eve ingest',
      );
      return c.json(IngestReport.parse(report), 202);
    },
  );

  return app;
}
