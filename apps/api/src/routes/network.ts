import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi';
import { asc, desc } from 'drizzle-orm';
import {
  ApiError,
  CreateSegmentRequest,
  NetworkSegment,
  TopologyGraph,
  TopologyRelationship,
} from '@noc/shared';
import type { Deps } from '../app-deps';
import { assets, networkSegments, topologyRelationships } from '../db/schema';
import { requirePermission } from '../middleware/auth';
import type { AppEnv } from '../middleware/context';

const err = (d: string) => ({
  description: d,
  content: { 'application/json': { schema: ApiError } },
});
const common = { 401: err('Unauthenticated'), 403: err('Forbidden') };
const NODE_LIMIT = 2000;
const EDGE_LIMIT = 5000;

const toSegment = (s: typeof networkSegments.$inferSelect) =>
  NetworkSegment.parse({
    id: s.id,
    name: s.name,
    site: s.site,
    cidr: s.cidr,
    vlanId: s.vlanId,
    activeDiscoveryAllowed: s.activeDiscoveryAllowed,
    description: s.description,
  });

export function networkRoutes(deps: Deps) {
  const { db } = deps;
  const app = new OpenAPIHono<AppEnv>();

  app.openapi(
    createRoute({
      method: 'get',
      path: '/segments',
      tags: ['network'],
      middleware: [requirePermission('network.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Segments',
          content: { 'application/json': { schema: z.array(NetworkSegment) } },
        },
        ...common,
      },
    }),
    async (c) =>
      c.json(
        (
          await db.select().from(networkSegments).orderBy(asc(networkSegments.name)).limit(1000)
        ).map(toSegment),
        200,
      ),
  );

  app.openapi(
    createRoute({
      method: 'post',
      path: '/segments',
      tags: ['network'],
      middleware: [requirePermission('network.manage')] as const,
      security: [{ bearerAuth: [] }],
      request: {
        body: { content: { 'application/json': { schema: CreateSegmentRequest } }, required: true },
      },
      responses: {
        201: {
          description: 'Created',
          content: { 'application/json': { schema: NetworkSegment } },
        },
        400: err('Validation'),
        ...common,
      },
    }),
    async (c) => {
      const body = c.req.valid('json');
      const p = c.get('principal')!;
      const row = await db.transaction(async (tx) => {
        const [s] = await tx.insert(networkSegments).values(body).returning();
        await deps.audit.record(
          {
            actorId: p.userId,
            actorLabel: p.email,
            action: 'network.segment_create',
            outcome: 'success',
            targetType: 'network_segment',
            targetId: s!.id,
            requestId: c.get('requestId'),
            sourceIp: c.get('clientIp'),
            metadata: {
              name: body.name,
              cidr: body.cidr,
              activeDiscoveryAllowed: body.activeDiscoveryAllowed,
            },
          },
          tx,
        );
        return s!;
      });
      return c.json(toSegment(row), 201);
    },
  );

  /** Nodes are assets; edges carry their verification label. Observed traffic is never cabling. */
  app.openapi(
    createRoute({
      method: 'get',
      path: '/topology',
      tags: ['network'],
      middleware: [requirePermission('network.read')] as const,
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'Topology graph',
          content: { 'application/json': { schema: TopologyGraph } },
        },
        ...common,
      },
    }),
    async (c) => {
      const nodes = await db
        .select({
          id: assets.id,
          hostname: assets.hostname,
          assetClass: assets.assetClass,
          segmentId: assets.segmentId,
          operationalStatus: assets.operationalStatus,
        })
        .from(assets)
        .orderBy(desc(assets.lastSeenAt))
        .limit(NODE_LIMIT + 1);
      const edges = await db
        .select()
        .from(topologyRelationships)
        .orderBy(desc(topologyRelationships.lastObservedAt))
        .limit(EDGE_LIMIT + 1);
      return c.json(
        TopologyGraph.parse({
          nodes: nodes.slice(0, NODE_LIMIT).map((n) => ({
            id: n.id,
            label: n.hostname ?? n.id.slice(0, 8),
            assetClass: n.assetClass,
            segmentId: n.segmentId,
            operationalStatus: n.operationalStatus,
          })),
          edges: edges.slice(0, EDGE_LIMIT).map((e) =>
            TopologyRelationship.parse({
              id: e.id,
              kind: e.kind,
              sourceAssetId: e.sourceAssetId,
              targetAssetId: e.targetAssetId,
              sourceInterfaceId: e.sourceInterfaceId,
              targetInterfaceId: e.targetInterfaceId,
              verification: e.verification,
              evidence: e.evidence,
              firstObservedAt: e.firstObservedAt.toISOString(),
              lastObservedAt: e.lastObservedAt.toISOString(),
            }),
          ),
          truncated: nodes.length > NODE_LIMIT || edges.length > EDGE_LIMIT,
          generatedAt: new Date().toISOString(),
        }),
        200,
      );
    },
  );

  return app;
}
