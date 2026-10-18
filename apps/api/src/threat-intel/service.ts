import { HTTPException } from 'hono/http-exception';
import {
  and,
  count,
  desc,
  eq,
  gt,
  ilike,
  inArray,
  isNull,
  max,
  notInArray,
  or,
  sql,
  type SQL,
} from 'drizzle-orm';
import {
  CLOSED_ALERT_STATUSES,
  IndicatorIndex,
  computeAlertPriority,
  extractObservables,
  indicatorAlertTitle,
  indicatorConfidence,
  parseIndicatorFeed,
  type AlertStreamEvent,
  type ImportIndicatorsRequest,
  type ImportIndicatorsResponse,
  type IndicatorHit,
  type IndicatorMatch,
  type IndicatorRecord,
  type IndicatorType,
  type MatchedField,
  type Severity,
  type ThreatIntelStats,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import {
  alerts,
  assets,
  securityEvents,
  threatIndicatorMatches,
  threatIndicators,
} from '../db/schema';
import type { AlertBusLike } from '../events/bus';

export interface Actor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

/** What the matcher needs from an event, whether it is being ingested or re-read from storage. */
export interface MatchContextEvent {
  eventId: string;
  eventTime: Date;
  sourceProduct: 'suricata' | 'zeek' | string;
  sourceSensorId: string | null;
  srcIp: string | null;
  dstIp: string | null;
  srcAssetId: string | null;
  dstAssetId: string | null;
  severity: Severity;
  engine: Record<string, unknown>;
}

type Row = typeof threatIndicators.$inferSelect;

const toIndicator = (r: Row): IndicatorRecord => ({
  id: r.id,
  type: r.type as IndicatorType,
  value: r.value,
  source: r.source,
  confidence: r.confidence,
  severity: r.severity,
  tags: r.tags,
  description: r.description,
  expiresAt: r.expiresAt?.toISOString() ?? null,
  revoked: r.revoked,
  importedAt: r.importedAt.toISOString(),
  updatedAt: r.updatedAt.toISOString(),
  matchCount: r.matchCount,
  lastMatchedAt: r.lastMatchedAt?.toISOString() ?? null,
});

const BATCH = 500;
export const RETRO_WINDOW_HOURS = 24;
const RETRO_MAX_EVENTS = 5000;
const INDEX_TTL_MS = 30_000;

const activeWhere = (now: Date): SQL =>
  and(
    eq(threatIndicators.revoked, false),
    or(isNull(threatIndicators.expiresAt), gt(threatIndicators.expiresAt, now)),
  )!;

/**
 * Indicators of compromise and their matches. Imports merge by (type, value) and only ever
 * widen what is known (a revocation is explicit, never implied by absence from a later feed).
 * Matching runs inline on every accepted ingest batch against a cached in-memory index and,
 * on import, retroactively over a bounded window of stored events — so a new indicator says
 * "seen yesterday" rather than waiting for the next sighting.
 */
export class ThreatIntelService {
  private index: { built: IndicatorIndex; at: number } | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly bus: AlertBusLike,
  ) {}

  invalidate(): void {
    this.index = null;
  }

  private async loadIndex(now = new Date()): Promise<IndicatorIndex> {
    if (this.index && now.getTime() - this.index.at < INDEX_TTL_MS) return this.index.built;
    const rows = await this.db
      .select({
        id: threatIndicators.id,
        type: threatIndicators.type,
        value: threatIndicators.value,
        source: threatIndicators.source,
        severity: threatIndicators.severity,
        confidence: threatIndicators.confidence,
      })
      .from(threatIndicators)
      .where(activeWhere(now))
      .limit(250_000);
    const built = new IndicatorIndex(rows.map((r) => ({ ...r, type: r.type as IndicatorType })));
    this.index = { built, at: now.getTime() };
    return built;
  }

  // ---- import / lifecycle -------------------------------------------------------------------
  async import(input: ImportIndicatorsRequest, actor: Actor): Promise<ImportIndicatorsResponse> {
    const parsed = parseIndicatorFeed(input.format, input.content, {
      source: input.source,
      defaultSeverity: input.defaultSeverity,
    });
    const res: ImportIndicatorsResponse = {
      parsed: parsed.records.length,
      imported: 0,
      updated: 0,
      unchanged: 0,
      revoked: 0,
      retroMatches: 0,
      retroWindowHours: RETRO_WINDOW_HOURS,
      errors: parsed.errors.slice(0, 20),
      errorCount: parsed.errors.length,
    };
    if (parsed.records.length === 0) {
      if (parsed.errors.length)
        throw new HTTPException(422, { message: `Feed rejected: ${parsed.errors[0]}` });
      return res;
    }
    const now = new Date();
    const touched: string[] = [];
    await this.db.transaction(async (tx) => {
      for (let i = 0; i < parsed.records.length; i += BATCH) {
        const slice = parsed.records.slice(i, i + BATCH);
        const existing = new Map(
          (
            await tx
              .select()
              .from(threatIndicators)
              .where(
                or(
                  ...slice.map((r) =>
                    and(eq(threatIndicators.type, r.type), eq(threatIndicators.value, r.value)),
                  ),
                )!,
              )
          ).map((r) => [`${r.type}|${r.value}`, r]),
        );
        const inserts: Array<typeof threatIndicators.$inferInsert> = [];
        for (const r of slice) {
          const cur = existing.get(`${r.type}|${r.value}`);
          if (!cur) {
            inserts.push({
              type: r.type,
              value: r.value,
              source: r.source,
              confidence: r.confidence ?? 50,
              severity: r.severity ?? input.defaultSeverity,
              tags: r.tags,
              description: r.description,
              expiresAt: r.expiresAt ? new Date(r.expiresAt) : null,
              revoked: r.revoked,
              importedAt: now,
              updatedAt: now,
            });
            if (r.revoked) res.revoked++;
            else res.imported++;
            continue;
          }
          const patch: Partial<typeof threatIndicators.$inferInsert> = {};
          if (r.revoked && !cur.revoked) {
            patch.revoked = true;
            res.revoked++;
          }
          // Re-asserting a revoked indicator un-revokes it only when the feed says so explicitly.
          if (!r.revoked && cur.revoked) patch.revoked = false;
          if (r.source !== cur.source) patch.source = r.source;
          if (r.confidence !== null && r.confidence !== cur.confidence)
            patch.confidence = r.confidence;
          if (r.severity !== null && r.severity !== cur.severity) patch.severity = r.severity;
          const tags = [...new Set([...cur.tags, ...r.tags])].slice(0, 32);
          if (tags.length !== cur.tags.length) patch.tags = tags;
          if (r.description && r.description !== cur.description) patch.description = r.description;
          const exp = r.expiresAt ? new Date(r.expiresAt) : null;
          if ((exp?.getTime() ?? null) !== (cur.expiresAt?.getTime() ?? null))
            patch.expiresAt = exp;
          if (Object.keys(patch).length === 0) {
            res.unchanged++;
            continue;
          }
          await tx
            .update(threatIndicators)
            .set({ ...patch, updatedAt: now })
            .where(eq(threatIndicators.id, cur.id));
          if (!patch.revoked) res.updated++;
          if (!r.revoked) touched.push(cur.id);
        }
        if (inserts.length) {
          const ins = await tx
            .insert(threatIndicators)
            .values(inserts)
            .returning({ id: threatIndicators.id, revoked: threatIndicators.revoked });
          for (const x of ins) if (!x.revoked) touched.push(x.id);
        }
      }
    });
    this.invalidate();
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'threat_intel.import',
      outcome: 'success',
      targetType: 'threat_indicators',
      targetId: null,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: {
        format: input.format,
        source: input.source,
        parsed: res.parsed,
        imported: res.imported,
        updated: res.updated,
        revoked: res.revoked,
        errorCount: res.errorCount,
      },
    });
    if (touched.length) res.retroMatches = await this.retroMatch(touched, now);
    return res;
  }

  async revoke(id: string, actor: Actor): Promise<IndicatorRecord> {
    const [row] = await this.db
      .update(threatIndicators)
      .set({ revoked: true, updatedAt: new Date() })
      .where(eq(threatIndicators.id, id))
      .returning();
    if (!row) throw new HTTPException(404, { message: 'Indicator not found' });
    this.invalidate();
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.label,
      action: 'threat_intel.revoke',
      outcome: 'success',
      targetType: 'threat_indicator',
      targetId: id,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: { type: row.type, value: row.value },
    });
    return toIndicator(row);
  }

  async list(q: {
    type?: IndicatorType;
    source?: string;
    q?: string;
    includeInactive: boolean;
    limit: number;
    offset: number;
  }): Promise<{ items: IndicatorRecord[]; total: number }> {
    const now = new Date();
    const conds: SQL[] = [];
    if (!q.includeInactive) conds.push(activeWhere(now));
    if (q.type) conds.push(eq(threatIndicators.type, q.type));
    if (q.source) conds.push(eq(threatIndicators.source, q.source));
    if (q.q) {
      const needle = `%${q.q.replace(/[%_\\]/g, (m) => `\\${m}`)}%`;
      conds.push(
        or(ilike(threatIndicators.value, needle), ilike(threatIndicators.description, needle))!,
      );
    }
    const where = conds.length ? and(...conds) : undefined;
    const [rows, [t]] = await Promise.all([
      this.db
        .select()
        .from(threatIndicators)
        .where(where)
        .orderBy(desc(threatIndicators.lastMatchedAt), desc(threatIndicators.updatedAt))
        .limit(q.limit)
        .offset(q.offset),
      this.db.select({ n: count() }).from(threatIndicators).where(where),
    ]);
    return { items: rows.map(toIndicator), total: t?.n ?? 0 };
  }

  async stats(): Promise<ThreatIntelStats> {
    const now = new Date();
    const [agg] = await this.db
      .select({
        total: count(),
        revoked: sql<number>`count(*) filter (where ${threatIndicators.revoked})::int`,
        expired: sql<number>`count(*) filter (where not ${threatIndicators.revoked} and ${threatIndicators.expiresAt} <= ${now.toISOString()}::timestamptz)::int`,
        lastImportAt: max(threatIndicators.importedAt),
      })
      .from(threatIndicators);
    const byType = await this.db
      .select({ type: threatIndicators.type, n: count() })
      .from(threatIndicators)
      .where(activeWhere(now))
      .groupBy(threatIndicators.type);
    const sources = await this.db
      .select({
        source: threatIndicators.source,
        active: sql<number>`count(*) filter (where not ${threatIndicators.revoked} and (${threatIndicators.expiresAt} is null or ${threatIndicators.expiresAt} > ${now.toISOString()}::timestamptz))::int`,
        lastImportAt: max(threatIndicators.importedAt),
      })
      .from(threatIndicators)
      .groupBy(threatIndicators.source)
      .orderBy(desc(max(threatIndicators.importedAt)))
      .limit(100);
    const [m] = await this.db
      .select({
        matches24h: sql<number>`count(*) filter (where ${threatIndicatorMatches.observedAt} > ${new Date(now.getTime() - 24 * 3_600_000).toISOString()}::timestamptz)::int`,
        lastMatchAt: max(threatIndicatorMatches.observedAt),
      })
      .from(threatIndicatorMatches);
    const total = agg?.total ?? 0;
    const revoked = Number(agg?.revoked ?? 0);
    const expired = Number(agg?.expired ?? 0);
    return {
      total,
      active: total - revoked - expired,
      expired,
      revoked,
      byType: Object.fromEntries(byType.map((b) => [b.type, b.n])),
      sources: sources.map((s) => ({
        source: s.source,
        active: Number(s.active),
        lastImportAt: s.lastImportAt!.toISOString(),
      })),
      lastImportAt: agg?.lastImportAt?.toISOString() ?? null,
      matches24h: Number(m?.matches24h ?? 0),
      lastMatchAt: m?.lastMatchAt?.toISOString() ?? null,
    };
  }

  async matches(opts: { limit: number; scope?: SQL }): Promise<IndicatorMatch[]> {
    const rows = await this.db
      .select({
        m: threatIndicatorMatches,
        type: threatIndicators.type,
        value: threatIndicators.value,
        source: threatIndicators.source,
        severity: threatIndicators.severity,
      })
      .from(threatIndicatorMatches)
      .innerJoin(threatIndicators, eq(threatIndicators.id, threatIndicatorMatches.indicatorId))
      .where(opts.scope)
      .orderBy(desc(threatIndicatorMatches.observedAt))
      .limit(opts.limit);
    return rows.map((r) => ({
      id: r.m.id,
      indicatorId: r.m.indicatorId,
      type: r.type as IndicatorType,
      value: r.value,
      source: r.source,
      severity: r.severity,
      eventId: r.m.eventId,
      alertId: r.m.alertId,
      assetId: r.m.assetId,
      sensorId: r.m.sensorId,
      matchedField: r.m.matchedField as MatchedField,
      matchedValue: r.m.matchedValue,
      observedAt: r.m.observedAt.toISOString(),
    }));
  }

  // ---- matching -----------------------------------------------------------------------------
  /**
   * Records hits for a batch of events and raises or bumps one alert per (indicator, src, dst).
   * Idempotent per (indicator, event, field). Returns the number of new match rows.
   */
  async matchEvents(
    events: readonly MatchContextEvent[],
    now = new Date(),
  ): Promise<{ matches: number; alertsCreated: number; alertsUpdated: number }> {
    const out = { matches: 0, alertsCreated: 0, alertsUpdated: 0 };
    if (events.length === 0) return out;
    const index = await this.loadIndex(now);
    if (index.size === 0) return out;
    const hits: Array<{ e: MatchContextEvent; h: IndicatorHit }> = [];
    for (const e of events) for (const h of index.match(extractObservables(e))) hits.push({ e, h });
    if (hits.length === 0) return out;

    const assetIds = [
      ...new Set(
        hits.flatMap(({ e }) => [e.dstAssetId, e.srcAssetId]).filter((x): x is string => !!x),
      ),
    ];
    const crit = new Map<string, (typeof assets.$inferSelect)['criticality']>();
    if (assetIds.length)
      for (const a of await this.db
        .select({ id: assets.id, criticality: assets.criticality })
        .from(assets)
        .where(inArray(assets.id, assetIds)))
        crit.set(a.id, a.criticality);

    for (const { e, h } of hits) {
      const assetId = e.dstAssetId ?? e.srcAssetId ?? null;
      const alertId = await this.upsertAlert(
        e,
        h,
        assetId,
        crit.get(assetId ?? '') ?? 'unclassified',
        now,
      );
      if (alertId.created) out.alertsCreated++;
      else if (alertId.updated) out.alertsUpdated++;
      const ins = await this.db
        .insert(threatIndicatorMatches)
        .values({
          indicatorId: h.indicator.id,
          eventId: e.eventId,
          alertId: alertId.id,
          assetId,
          sensorId: e.sourceSensorId,
          matchedField: h.field,
          matchedValue: h.value,
          observedAt: e.eventTime,
          createdAt: now,
        })
        .onConflictDoNothing()
        .returning({ id: threatIndicatorMatches.id });
      if (ins.length) {
        out.matches++;
        await this.db
          .update(threatIndicators)
          .set({
            matchCount: sql`${threatIndicators.matchCount} + 1`,
            lastMatchedAt: sql`greatest(coalesce(${threatIndicators.lastMatchedAt}, 'epoch'::timestamptz), ${e.eventTime.toISOString()}::timestamptz)`,
          })
          .where(eq(threatIndicators.id, h.indicator.id));
      }
    }
    return out;
  }

  private async upsertAlert(
    e: MatchContextEvent,
    h: IndicatorHit,
    assetId: string | null,
    criticality: (typeof assets.$inferSelect)['criticality'],
    now: Date,
  ): Promise<{ id: string; created: boolean; updated: boolean }> {
    const key = `ti:${h.indicator.id}:${e.srcIp ?? '-'}:${e.dstIp ?? '-'}`;
    const confidence = indicatorConfidence(h.indicator.confidence);
    const priority = computeAlertPriority({
      severity: h.indicator.severity,
      confidence,
      assetCriticality: criticality,
    }).score;
    const title = indicatorAlertTitle(h);
    const [open] = await this.db
      .select({
        id: alerts.id,
        lastSeenAt: alerts.lastSeenAt,
        firstSeenAt: alerts.firstSeenAt,
        lastEventId: alerts.lastEventId,
      })
      .from(alerts)
      .where(and(eq(alerts.dedupKey, key), notInArray(alerts.status, [...CLOSED_ALERT_STATUSES])))
      .limit(1);
    if (open) {
      // The same event re-read retroactively must not count twice.
      if (open.lastEventId === e.eventId) return { id: open.id, created: false, updated: false };
      await this.db
        .update(alerts)
        .set({
          occurrenceCount: sql`${alerts.occurrenceCount} + 1`,
          lastSeenAt: e.eventTime > open.lastSeenAt ? e.eventTime : open.lastSeenAt,
          firstSeenAt: e.eventTime < open.firstSeenAt ? e.eventTime : open.firstSeenAt,
          lastEventId: e.eventId,
          priorityScore: sql`greatest(${alerts.priorityScore}, ${priority})`,
          updatedAt: now,
        })
        .where(eq(alerts.id, open.id));
      this.publish({
        kind: 'updated',
        alertId: open.id,
        severity: h.indicator.severity,
        title,
        at: now.toISOString(),
      });
      return { id: open.id, created: false, updated: true };
    }
    const [created] = await this.db
      .insert(alerts)
      .values({
        title,
        status: 'new',
        severity: h.indicator.severity,
        confidence,
        priorityScore: priority,
        ruleId: null,
        ruleRef: `ti:${h.indicator.type}:${h.indicator.value}`.slice(0, 256),
        sourceProduct:
          e.sourceProduct === 'zeek'
            ? 'zeek'
            : e.sourceProduct === 'suricata'
              ? 'suricata'
              : 'platform',
        sourceSensorId: e.sourceSensorId,
        assetId,
        srcIp: e.srcIp,
        dstIp: e.dstIp,
        dedupKey: key,
        occurrenceCount: 1,
        firstSeenAt: e.eventTime,
        lastSeenAt: e.eventTime,
        lastEventId: e.eventId,
        updatedAt: now,
      })
      .returning({ id: alerts.id });
    this.publish({
      kind: 'created',
      alertId: created!.id,
      severity: h.indicator.severity,
      title,
      at: now.toISOString(),
    });
    return { id: created!.id, created: true, updated: false };
  }

  private publish(ev: AlertStreamEvent): void {
    try {
      this.bus.publish(ev);
    } catch {
      /* a broken subscriber must not fail matching */
    }
  }

  /** Re-reads the last RETRO_WINDOW_HOURS of events against the given indicators only. */
  async retroMatch(indicatorIds: readonly string[], now = new Date()): Promise<number> {
    const rows = await this.db
      .select({
        id: threatIndicators.id,
        type: threatIndicators.type,
        value: threatIndicators.value,
        source: threatIndicators.source,
        severity: threatIndicators.severity,
        confidence: threatIndicators.confidence,
      })
      .from(threatIndicators)
      .where(and(inArray(threatIndicators.id, [...indicatorIds]), activeWhere(now)));
    if (rows.length === 0) return 0;
    const index = new IndicatorIndex(rows.map((r) => ({ ...r, type: r.type as IndicatorType })));
    const since = new Date(now.getTime() - RETRO_WINDOW_HOURS * 3_600_000);
    const events = await this.db
      .select({
        eventId: securityEvents.id,
        eventTime: securityEvents.eventTime,
        sourceProduct: securityEvents.sourceProduct,
        sourceSensorId: securityEvents.sourceSensorId,
        srcIp: securityEvents.srcIp,
        dstIp: securityEvents.dstIp,
        srcAssetId: securityEvents.srcAssetId,
        dstAssetId: securityEvents.dstAssetId,
        severity: securityEvents.severity,
        engine: securityEvents.engine,
      })
      .from(securityEvents)
      .where(gt(securityEvents.eventTime, since))
      .orderBy(desc(securityEvents.eventTime))
      .limit(RETRO_MAX_EVENTS);
    // Same path as live ingest, but against the fresh indicators only.
    const saved = this.index;
    this.index = { built: index, at: now.getTime() };
    try {
      return (await this.matchEvents(events, now)).matches;
    } finally {
      this.index = saved;
    }
  }
}
