import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, gte, lte, notInArray, sql, type SQL } from 'drizzle-orm';
import {
  Alert,
  AlertDetail,
  AlertListQuery,
  AlertTriageRequest,
  ApiError,
  CLOSED_ALERT_STATUSES,
  EventStats,
  EventsQuery,
  NormalizedEvent,
  SeverityValues,
  validateAlertTransition,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { alerts, securityEvents, sensors } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const MAX_RANGE_MS = 7 * 24 * 3600 * 1000;

export const toAlert = (a: typeof alerts.$inferSelect) =>
  Alert.parse({
    id: a.id,
    title: a.title,
    status: a.status,
    severity: a.severity,
    confidence: a.confidence,
    priorityScore: a.priorityScore,
    ruleId: a.ruleId,
    sourceProduct: a.sourceProduct,
    assetId: a.assetId,
    dedupKey: a.dedupKey,
    occurrenceCount: a.occurrenceCount,
    firstSeenAt: a.firstSeenAt.toISOString(),
    lastSeenAt: a.lastSeenAt.toISOString(),
    assigneeId: a.assigneeId,
    incidentId: a.incidentId,
    suppressedUntil: a.suppressedUntil?.toISOString() ?? null,
    dispositionNote: a.dispositionNote,
  });

export const toEvent = (e: typeof securityEvents.$inferSelect) =>
  NormalizedEvent.parse({
    schemaVersion: e.schemaVersion,
    eventId: e.id,
    eventTime: e.eventTime.toISOString(),
    ingestTime: e.ingestTime.toISOString(),
    sourceProduct: e.sourceProduct,
    sourceSensorId: e.sourceSensorId,
    category: e.category,
    type: e.type,
    severity: e.severity,
    confidence: e.confidence,
    srcAssetId: e.srcAssetId,
    dstAssetId: e.dstAssetId,
    srcIp: e.srcIp,
    dstIp: e.dstIp,
    srcPort: e.srcPort,
    dstPort: e.dstPort,
    protocol: e.protocol,
    ruleId: e.ruleId,
    threatClassification: e.threatClassification,
    incidentId: e.incidentId,
    evidenceRefs: e.evidenceRefs,
    correlationIds: e.correlationIds,
    originalRef: e.originalRef ?? null,
    engine: e.engine,
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

export function alertRoutes(deps: Deps) {
  const { db, audit } = deps;
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['alerts'],
      middleware: [requirePermission('alerts.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: AlertListQuery },
      responses: {
        200: {
          description: 'Alerts, most recently seen first',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(Alert), nextCursor: z.string().nullable() }),
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
      if (q.status) conds.push(eq(alerts.status, q.status));
      if (q.open) conds.push(notInArray(alerts.status, [...CLOSED_ALERT_STATUSES]));
      if (q.severity) conds.push(eq(alerts.severity, q.severity));
      if (q.assetId) conds.push(eq(alerts.assetId, q.assetId));
      if (q.cursor) {
        const k = decodeCursor(q.cursor);
        conds.push(
          sql`(${alerts.lastSeenAt}, ${alerts.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await db
        .select()
        .from(alerts)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(alerts.lastSeenAt), desc(alerts.id))
        .limit(q.limit + 1);
      const page = rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(toAlert),
          nextCursor: rows.length > q.limit && last ? encodeCursor(last.lastSeenAt, last.id) : null,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}',
      tags: ['alerts'],
      middleware: [requirePermission('alerts.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: z.object({ id: z.uuid() }) },
      responses: {
        200: {
          description: 'Alert with its most recent contributing events',
          content: { 'application/json': { schema: AlertDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const [a] = await db.select().from(alerts).where(eq(alerts.id, id)).limit(1);
      if (!a) throw new HTTPException(404, { message: 'Alert not found' });
      const conds: SQL[] = [eq(securityEvents.type, 'alert')];
      if (a.ruleRef) conds.push(eq(securityEvents.ruleId, a.ruleRef));
      if (a.sourceSensorId) conds.push(eq(securityEvents.sourceSensorId, a.sourceSensorId));
      if (a.srcIp) conds.push(eq(securityEvents.srcIp, a.srcIp));
      if (a.dstIp) conds.push(eq(securityEvents.dstIp, a.dstIp));
      const recent = await db
        .select()
        .from(securityEvents)
        .where(and(...conds))
        .orderBy(desc(securityEvents.eventTime))
        .limit(20);
      return c.json(
        {
          alert: {
            ...toAlert(a),
            ruleRef: a.ruleRef,
            srcIp: a.srcIp,
            dstIp: a.dstIp,
            sourceSensorId: a.sourceSensorId,
          },
          recentEvents: recent.map(toEvent),
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'patch',
      path: '/{id}',
      tags: ['alerts'],
      middleware: [requirePermission('alerts.triage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: z.object({ id: z.uuid() }),
        body: { content: { 'application/json': { schema: AlertTriageRequest } }, required: true },
      },
      responses: {
        200: { description: 'Updated', content: { 'application/json': { schema: Alert } } },
        400: err('Validation'),
        404: err('Not found'),
        409: err('Transition not allowed'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const body = c.req.valid('json');
      const p = c.get('principal')!;
      const row = await db.transaction(async (tx) => {
        const [a] = await tx.select().from(alerts).where(eq(alerts.id, id)).limit(1).for('update');
        if (!a) throw new HTTPException(404, { message: 'Alert not found' });
        const t = validateAlertTransition(a.status, body.action, body.note);
        if (!t.ok) throw new HTTPException(409, { message: t.message });
        if (body.action === 'suppress' && new Date(body.suppressedUntil!).getTime() <= Date.now())
          throw new HTTPException(400, { message: 'suppressedUntil must be in the future' });
        const [updated] = await tx
          .update(alerts)
          .set({
            status: t.to,
            assigneeId:
              body.assigneeId !== undefined
                ? body.assigneeId
                : body.action === 'acknowledge' || body.action === 'investigate'
                  ? p.userId
                  : a.assigneeId,
            suppressedUntil:
              body.action === 'suppress'
                ? new Date(body.suppressedUntil!)
                : t.to === 'new'
                  ? null
                  : a.suppressedUntil,
            dispositionNote: body.note ?? a.dispositionNote,
            updatedAt: new Date(),
          })
          .where(eq(alerts.id, id))
          .returning();
        await audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'alerts.triage',
            outcome: 'success',
            targetType: 'alert',
            targetId: id,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: {
              from: a.status,
              action: body.action,
              to: t.to,
              note: body.note ?? null,
              suppressedUntil: body.suppressedUntil ?? null,
            },
          },
          tx,
        );
        return updated!;
      });
      return c.json(toAlert(row), 200);
    },
  );

  return app;
}

export function eventRoutes(deps: Deps) {
  const { db } = deps;
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/stats',
      tags: ['events'],
      middleware: [requirePermission('events.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: z.object({ hours: z.coerce.number().int().min(1).max(168).default(24) }) },
      responses: {
        200: {
          description: 'Ingestion statistics',
          content: { 'application/json': { schema: EventStats } },
        },
        ...common,
      },
    }),
    async (c) => {
      const { hours } = c.req.valid('query');
      const now = new Date();
      const since = new Date(now.getTime() - hours * 3600_000);
      const byType = await db
        .select({ k: securityEvents.type, n: count() })
        .from(securityEvents)
        .where(gte(securityEvents.eventTime, since))
        .groupBy(securityEvents.type);
      const bySev = await db
        .select({ k: securityEvents.severity, n: count() })
        .from(securityEvents)
        .where(gte(securityEvents.eventTime, since))
        .groupBy(securityEvents.severity);
      const perSensor = await db
        .select({ k: securityEvents.sourceSensorId, n: count() })
        .from(securityEvents)
        .where(gte(securityEvents.eventTime, since))
        .groupBy(securityEvents.sourceSensorId);
      const engineSensors = await db
        .select()
        .from(sensors)
        .where(sql`${sensors.kind} in ('suricata','zeek')`)
        .limit(500);
      return c.json(
        EventStats.parse({
          windowHours: hours,
          byType: Object.fromEntries(byType.map((r) => [r.k, r.n])),
          bySeverity: Object.fromEntries(
            SeverityValues.map((s) => [s, bySev.find((r) => r.k === s)?.n ?? 0]),
          ),
          total: byType.reduce((a, r) => a + r.n, 0),
          sensors: engineSensors.map((s) => ({
            sensorId: s.id,
            name: s.name,
            kind: s.kind,
            lastEventAt: s.lastEventAt?.toISOString() ?? null,
            lagSeconds: s.lastEventAt ? (now.getTime() - s.lastEventAt.getTime()) / 1000 : null,
            events: perSensor.find((r) => r.k === s.id)?.n ?? 0,
          })),
          generatedAt: now.toISOString(),
        }),
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['events'],
      middleware: [requirePermission('events.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: EventsQuery },
      responses: {
        200: {
          description: 'Events in range, newest first (bounded: ≤ 7 days, ≤ 500 per page)',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(NormalizedEvent),
                nextCursor: z.string().nullable(),
              }),
            },
          },
        },
        400: err('Validation / range too large'),
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const from = new Date(q.from);
      const to = new Date(q.to);
      if (to <= from) throw new HTTPException(400, { message: 'to must be after from' });
      if (to.getTime() - from.getTime() > MAX_RANGE_MS)
        throw new HTTPException(400, { message: 'Range exceeds 7 days' });
      const conds: SQL[] = [gte(securityEvents.eventTime, from), lte(securityEvents.eventTime, to)];
      if (q.sensorId) conds.push(eq(securityEvents.sourceSensorId, q.sensorId));
      if (q.category) conds.push(eq(securityEvents.category, q.category));
      if (q.type) conds.push(eq(securityEvents.type, q.type));
      if (q.severity) conds.push(eq(securityEvents.severity, q.severity));
      if (q.ruleId) conds.push(eq(securityEvents.ruleId, q.ruleId));
      if (q.ip)
        conds.push(
          sql`(${securityEvents.srcIp} = ${q.ip}::inet or ${securityEvents.dstIp} = ${q.ip}::inet)`,
        );
      if (q.assetId)
        conds.push(
          sql`(${securityEvents.srcAssetId} = ${q.assetId}::uuid or ${securityEvents.dstAssetId} = ${q.assetId}::uuid)`,
        );
      if (q.cursor) {
        const k = decodeCursor(q.cursor);
        conds.push(
          sql`(${securityEvents.eventTime}, ${securityEvents.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await db
        .select()
        .from(securityEvents)
        .where(and(...conds))
        .orderBy(desc(securityEvents.eventTime), desc(securityEvents.id))
        .limit(q.limit + 1);
      const page = rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(toEvent),
          nextCursor: rows.length > q.limit && last ? encodeCursor(last.eventTime, last.id) : null,
        },
        200,
      );
    },
  );

  return app;
}
