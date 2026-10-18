import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, ilike, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import {
  ApiError,
  Asset,
  AssetCoverageSummary,
  AssetDetail,
  AssetInterface,
  AssetListQuery,
  AssetObservation,
  AssetPatchRequest,
  AssetTimelineEntry,
  AssuranceStateValues,
  CoverageStateValues,
  IngestObservationRequest,
  IngestObservationResponse,
  PageQuery,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { AssetService } from '../assets/service';
import { assetInterfaces, assetObservations, assets, auditEvents } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';
import { rateLimit } from '../middleware/rate-limit';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
type AssetRow = typeof assets.$inferSelect;
type IfaceRow = typeof assetInterfaces.$inferSelect;

function toPublicInterface(r: IfaceRow) {
  return AssetInterface.parse({
    id: r.id,
    assetId: r.assetId,
    name: r.name,
    macAddress: r.macAddress?.toLowerCase() ?? null,
    ipAddresses: r.ipAddresses,
    speedMbps: r.speedMbps,
    adminState: r.adminState,
    operState: r.operState,
    vlanId: r.vlanId,
  });
}

/** `serialNumber` is only revealed to holders of assets.read_sensitive. */
function toPublicAsset(r: AssetRow, ifaces: IfaceRow[], sensitive: boolean) {
  return Asset.parse({
    id: r.id,
    hostname: r.hostname,
    ipAddresses: [...new Set(ifaces.flatMap((i) => i.ipAddresses))].slice(0, 64),
    assetClass: r.assetClass,
    manufacturer: r.manufacturer,
    model: r.model,
    serialNumber: sensitive ? r.serialNumber : null,
    osName: r.osName,
    osVersion: r.osVersion,
    firmwareVersion: r.firmwareVersion,
    cpuArchitecture: r.cpuArchitecture,
    ramMb: r.ramMb,
    segmentId: r.segmentId,
    role: r.role,
    criticality: r.criticality,
    owner: r.owner,
    responsibleTeam: r.responsibleTeam,
    discoveryMethods: r.discoveryMethods,
    firstSeenAt: r.firstSeenAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    operationalStatus: r.operationalStatus,
    monitoringCoverage: r.monitoringCoverage,
    credentialedAssessmentStatus: r.credentialedAssessmentStatus,
    assuranceState: r.assuranceState,
    dataConfidence: r.dataConfidence,
    provenance: Array.isArray(r.provenance) ? r.provenance : [],
  });
}

function toPublicObservation(o: typeof assetObservations.$inferSelect) {
  return AssetObservation.parse({
    id: o.id,
    assetId: o.assetId,
    source: o.source,
    method: o.method,
    observedAt: o.observedAt.toISOString(),
    identifiers: {
      macAddresses: o.macAddresses.map((m) => m.toLowerCase()),
      ipAddresses: o.ipAddresses,
      hostnames: o.hostnames,
      ...(o.cloudInstanceId ? { cloudInstanceId: o.cloudInstanceId } : {}),
      ...(o.agentId ? { agentId: o.agentId } : {}),
    },
    attributes: o.attributes,
    conflictsWith: o.conflictsWith,
  });
}

const encodeCursor = (d: Date, id: string) =>
  Buffer.from(`${d.toISOString()}|${id}`).toString('base64url');
function decodeCursor(c: string): { at: Date; id: string } {
  const [iso, id] = Buffer.from(c, 'base64url').toString().split('|');
  const at = new Date(iso ?? '');
  if (!id || Number.isNaN(at.getTime()) || !/^[0-9a-f-]{36}$/.test(id))
    throw new HTTPException(400, { message: 'Invalid cursor' });
  return { at, id };
}
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

export function assetRoutes(deps: Deps) {
  const { db, limiter } = deps;
  const service = new AssetService(db, deps.audit);
  const app = new OpenAPIHono<AppEnv>();

  // ---- POST /observations (collectors) -----------------------------------------------------
  app.openapi(
    createRoute({
      method: 'post',
      path: '/observations',
      tags: ['assets'],
      middleware: [
        requirePermission('discovery.run_passive'),
        rateLimit(limiter, {
          name: 'ingest',
          capacity: 600,
          refillPerSecond: 20,
          keyBy: 'ip+user',
        }),
      ] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: { 'application/json': { schema: IngestObservationRequest } },
          required: true,
        },
      },
      responses: {
        201: {
          description: 'Observation stored and resolved',
          content: { 'application/json': { schema: IngestObservationResponse } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const p = c.get('principal')!;
      const r = await service.ingest(c.req.valid('json'), {
        userId: p.userId,
        label: p.email,
        requestId: c.get('requestId'),
        ip: c.get('clientIp'),
      });
      const d = r.decision;
      return c.json(
        IngestObservationResponse.parse({
          observationId: r.observationId,
          assetId: r.assetId,
          decision: d.action,
          reason: d.reason,
          confidence: d.action === 'ambiguous' ? null : d.confidence,
          conflicts: d.action === 'match' ? d.conflicts : [],
          candidateIds: d.action === 'ambiguous' ? d.candidateIds : [],
        }),
        201,
      );
    },
  );

  // ---- GET /coverage -----------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/coverage',
      tags: ['assets'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Coverage summary',
          content: { 'application/json': { schema: AssetCoverageSummary } },
        },
        ...common,
      },
    }),
    async (c) => {
      const [total] = await db.select({ n: count() }).from(assets);
      const byCov = await db
        .select({ k: assets.monitoringCoverage, n: count() })
        .from(assets)
        .groupBy(assets.monitoringCoverage);
      const byAss = await db
        .select({ k: assets.assuranceState, n: count() })
        .from(assets)
        .groupBy(assets.assuranceState);
      const byCls = await db
        .select({ k: assets.assetClass, n: count() })
        .from(assets)
        .groupBy(assets.assetClass);
      const [unresolved] = await db
        .select({ n: count() })
        .from(assetObservations)
        .where(isNull(assetObservations.assetId));
      return c.json(
        AssetCoverageSummary.parse({
          total: total?.n ?? 0,
          byCoverage: Object.fromEntries(
            CoverageStateValues.map((k) => [k, byCov.find((r) => r.k === k)?.n ?? 0]),
          ),
          byAssurance: Object.fromEntries(
            AssuranceStateValues.map((k) => [k, byAss.find((r) => r.k === k)?.n ?? 0]),
          ),
          byClass: Object.fromEntries(byCls.map((r) => [r.k, r.n])),
          unresolvedObservations: unresolved?.n ?? 0,
          generatedAt: new Date().toISOString(),
        }),
        200,
      );
    },
  );

  // ---- GET / -------------------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/',
      tags: ['assets'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { query: AssetListQuery },
      responses: {
        200: {
          description: 'Assets, most recently seen first',
          content: {
            'application/json': {
              schema: z.object({ items: z.array(Asset), nextCursor: z.string().nullable() }),
            },
          },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const q = c.req.valid('query');
      const sensitive = c.get('principal')!.permissions.has('assets.read_sensitive');
      const conds: SQL[] = [];
      if (q.segmentId) conds.push(eq(assets.segmentId, q.segmentId));
      if (q.assetClass) conds.push(eq(assets.assetClass, q.assetClass));
      if (q.coverage) conds.push(eq(assets.monitoringCoverage, q.coverage));
      if (q.status) conds.push(eq(assets.operationalStatus, q.status));
      if (q.q) conds.push(ilike(assets.hostname, `%${escapeLike(q.q)}%`));
      if (q.cursor) {
        const { at, id } = decodeCursor(q.cursor);
        conds.push(
          sql`(${assets.lastSeenAt}, ${assets.id}) < (${at.toISOString()}::timestamptz, ${id}::uuid)`,
        );
      }
      const rows = await db
        .select()
        .from(assets)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(assets.lastSeenAt), desc(assets.id))
        .limit(q.limit + 1);
      const page = rows.slice(0, q.limit);
      const ifaces = page.length
        ? await db
            .select()
            .from(assetInterfaces)
            .where(
              inArray(
                assetInterfaces.assetId,
                page.map((r) => r.id),
              ),
            )
        : [];
      const items = page.map((r) =>
        toPublicAsset(
          r,
          ifaces.filter((i) => i.assetId === r.id),
          sensitive,
        ),
      );
      const last = page[page.length - 1];
      return c.json(
        {
          items,
          nextCursor: rows.length > q.limit && last ? encodeCursor(last.lastSeenAt, last.id) : null,
        },
        200,
      );
    },
  );

  const idParam = z.object({ id: z.uuid() });

  // ---- GET /{id} ---------------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}',
      tags: ['assets'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Asset with interfaces',
          content: { 'application/json': { schema: AssetDetail } },
        },
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const [row] = await db.select().from(assets).where(eq(assets.id, id)).limit(1);
      if (!row) throw new HTTPException(404, { message: 'Asset not found' });
      const ifaces = await db.select().from(assetInterfaces).where(eq(assetInterfaces.assetId, id));
      const sensitive = c.get('principal')!.permissions.has('assets.read_sensitive');
      return c.json(
        { asset: toPublicAsset(row, ifaces, sensitive), interfaces: ifaces.map(toPublicInterface) },
        200,
      );
    },
  );

  // ---- PATCH /{id} (metadata only; never identity) -----------------------------------------
  app.openapi(
    createRoute({
      method: 'patch',
      path: '/{id}',
      tags: ['assets'],
      middleware: [requirePermission('assets.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        params: idParam,
        body: { content: { 'application/json': { schema: AssetPatchRequest } }, required: true },
      },
      responses: {
        200: { description: 'Updated', content: { 'application/json': { schema: Asset } } },
        400: err('Validation'),
        404: err('Not found'),
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const patch = c.req.valid('json');
      const p = c.get('principal')!;
      const row = await db.transaction(async (tx) => {
        const [updated] = await tx
          .update(assets)
          .set({ ...patch, updatedAt: new Date() })
          .where(eq(assets.id, id))
          .returning();
        if (!updated) throw new HTTPException(404, { message: 'Asset not found' });
        await deps.audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'assets.update',
            outcome: 'success',
            targetType: 'asset',
            targetId: id,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: { fields: Object.keys(patch) },
          },
          tx,
        );
        return updated;
      });
      const ifaces = await db.select().from(assetInterfaces).where(eq(assetInterfaces.assetId, id));
      return c.json(toPublicAsset(row, ifaces, p.permissions.has('assets.read_sensitive')), 200);
    },
  );

  // ---- GET /{id}/observations --------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}/observations',
      tags: ['assets'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam, query: PageQuery },
      responses: {
        200: {
          description: 'Observations, newest first',
          content: {
            'application/json': {
              schema: z.object({
                items: z.array(AssetObservation),
                nextCursor: z.string().nullable(),
              }),
            },
          },
        },
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const { limit, cursor } = c.req.valid('query');
      const conds: SQL[] = [eq(assetObservations.assetId, id)];
      if (cursor) {
        const k = decodeCursor(cursor);
        conds.push(
          sql`(${assetObservations.observedAt}, ${assetObservations.id}) < (${k.at.toISOString()}::timestamptz, ${k.id}::uuid)`,
        );
      }
      const rows = await db
        .select()
        .from(assetObservations)
        .where(and(...conds))
        .orderBy(desc(assetObservations.observedAt), desc(assetObservations.id))
        .limit(limit + 1);
      const page = rows.slice(0, limit);
      const last = page[page.length - 1];
      return c.json(
        {
          items: page.map(toPublicObservation),
          nextCursor: rows.length > limit && last ? encodeCursor(last.observedAt, last.id) : null,
        },
        200,
      );
    },
  );

  // ---- GET /{id}/timeline ------------------------------------------------------------------
  app.openapi(
    createRoute({
      method: 'get',
      path: '/{id}/timeline',
      tags: ['assets'],
      middleware: [requirePermission('assets.read')] as const,
      security: [{ bearerAuth: [] }],
      request: { params: idParam },
      responses: {
        200: {
          description: 'Merged observation + audit timeline (latest 200)',
          content: { 'application/json': { schema: z.array(AssetTimelineEntry) } },
        },
        ...common,
      },
    }),
    async (c) => {
      const { id } = c.req.valid('param');
      const obs = await db
        .select()
        .from(assetObservations)
        .where(eq(assetObservations.assetId, id))
        .orderBy(desc(assetObservations.observedAt))
        .limit(100);
      const aud = await db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.targetType, 'asset'), eq(auditEvents.targetId, id)))
        .orderBy(desc(auditEvents.occurredAt))
        .limit(100);
      const entries = [
        ...obs.map((o) => ({
          at: o.observedAt.toISOString(),
          kind: 'observation' as const,
          summary: `${o.method} via ${o.source}`,
          ref: o.id,
        })),
        ...aud.map((a) => ({
          at: a.occurredAt.toISOString(),
          kind: 'audit' as const,
          summary: `${a.action} (${a.outcome}) by ${a.actorLabel}`,
          ref: String(a.seq),
        })),
      ]
        .sort((x, y) => y.at.localeCompare(x.at))
        .slice(0, 200);
      return c.json(z.array(AssetTimelineEntry).parse(entries), 200);
    },
  );

  return app;
}
