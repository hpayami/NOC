import { createHash, randomUUID } from 'node:crypto';
import { and, eq, inArray, notInArray, sql } from 'drizzle-orm';
import {
  CLOSED_ALERT_STATUSES,
  INGEST_MAX_RECORDS,
  alertTitleFor,
  computeAlertPriority,
  normalizeEveRecord,
  normalizeZeekRecord,
  type AlertStreamEvent,
  type IngestReport,
  type NormalizedEvent,
} from '@noc/shared';
import { HTTPException } from 'hono/http-exception';
import type { Db } from '../db/client';
import { alerts, assets, securityEvents, sensors } from '../db/schema';
import type { Metrics } from '../platform/metrics';
import type { AlertBusLike } from './bus';
import { resolveRuleIds } from '../rules/service';
import type { ThreatIntelService } from '../threat-intel/service';

export interface IngestSource {
  sensorId: string;
  sensorName: string;
  kind: string;
}

/** Stable identity of one engine event: same event re-sent by a restarting forwarder is one event. */
export function dedupHash(e: NormalizedEvent): string {
  const flow = (e.engine.flow_id as string | number | undefined) ?? '';
  const material = [
    e.sourceProduct,
    e.sourceSensorId ?? '',
    e.eventTime,
    e.type,
    e.srcIp ?? '',
    e.srcPort ?? '',
    e.dstIp ?? '',
    e.dstPort ?? '',
    e.protocol ?? '',
    e.ruleId ?? '',
    String(flow),
  ].join('|');
  return createHash('sha256').update(material).digest('hex');
}

/** Splits an NDJSON or JSON-array body into raw records without throwing on bad lines. */
export function splitRecords(body: string): Array<{ index: number; raw: unknown; error?: string }> {
  const trimmed = body.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed) as unknown;
      if (!Array.isArray(arr)) return [{ index: 0, raw: null, error: 'body_not_array' }];
      return arr.map((raw, index) => ({ index, raw }));
    } catch {
      return [{ index: 0, raw: null, error: 'invalid_json' }];
    }
  }
  return trimmed.split('\n').map((line, index) => {
    const l = line.trim();
    if (!l) return { index, raw: null, error: 'empty_line' };
    try {
      return { index, raw: JSON.parse(l) as unknown };
    } catch {
      return { index, raw: null, error: 'invalid_json' };
    }
  });
}

/**
 * Suricata EVE → security_events + alert queue. Bounded (≤ INGEST_MAX_RECORDS per call),
 * idempotent (dedup hash), explicit about rejections, and it never stores packet payloads.
 */
export class EventPipeline {
  constructor(
    private readonly db: Db,
    private readonly metrics: Metrics,
    private readonly bus: AlertBusLike,
    private readonly threatIntel?: Pick<ThreatIntelService, 'matchEvents'>,
  ) {}

  async ingestEve(body: string, source: IngestSource): Promise<IngestReport> {
    return this.ingest(body, source, 'suricata');
  }

  async ingestZeek(
    body: string,
    source: IngestSource,
    defaultPath?: string,
  ): Promise<IngestReport> {
    return this.ingest(body, source, 'zeek', defaultPath);
  }

  async ingest(
    body: string,
    source: IngestSource,
    product: 'suricata' | 'zeek',
    defaultPath?: string,
  ): Promise<IngestReport> {
    const records = splitRecords(body).filter((r) => r.error !== 'empty_line');
    if (records.length > INGEST_MAX_RECORDS)
      throw new HTTPException(413, {
        message: `At most ${INGEST_MAX_RECORDS} records per request`,
      });
    const ingestTime = new Date();
    const report: IngestReport = {
      received: records.length,
      accepted: 0,
      duplicates: 0,
      rejected: 0,
      rejections: [],
      alertsCreated: 0,
      alertsUpdated: 0,
      indicatorMatches: 0,
      maxEventLagSeconds: null,
    };
    const reject = (index: number, reason: string) => {
      report.rejected++;
      if (report.rejections.length < 20) report.rejections.push({ index, reason });
      this.metrics.eventsRejected.inc({ reason: reason.split(':')[0] ?? reason });
    };

    const events: NormalizedEvent[] = [];
    for (const r of records) {
      if (r.error) {
        reject(r.index, r.error);
        continue;
      }
      const ctx = {
        sensorId: source.sensorId,
        eventId: randomUUID(),
        ingestTime: ingestTime.toISOString(),
      };
      const n =
        product === 'suricata'
          ? normalizeEveRecord(r.raw, ctx)
          : normalizeZeekRecord(r.raw, { ...ctx, defaultPath });
      if (!n.ok) reject(r.index, n.reason);
      else events.push(n.event);
    }
    if (events.length === 0) return report;

    // Asset correlation by address, one query for the whole batch.
    const ips = [
      ...new Set(events.flatMap((e) => [e.srcIp, e.dstIp]).filter((x): x is string => !!x)),
    ];
    const assetByIp = new Map<string, string>();
    if (ips.length) {
      const rows = (await this.db.execute(
        sql`select asset_id, host(ip)::text as ip from asset_interfaces, unnest(ip_addresses) as ip where ip_addresses && ARRAY[${sql.join(
          ips.map((ip) => sql`${ip}::inet`),
          sql`, `,
        )}]`,
      )) as unknown as Array<{ asset_id: string; ip: string }>;
      for (const r of rows) if (!assetByIp.has(r.ip)) assetByIp.set(r.ip, r.asset_id);
    }
    for (const e of events) {
      e.srcAssetId = e.srcIp ? (assetByIp.get(e.srcIp) ?? null) : null;
      e.dstAssetId = e.dstIp ? (assetByIp.get(e.dstIp) ?? null) : null;
    }

    const inserted = await this.db
      .insert(securityEvents)
      .values(
        events.map((e) => ({
          id: e.eventId,
          schemaVersion: e.schemaVersion,
          eventTime: new Date(e.eventTime),
          ingestTime,
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
          incidentId: null,
          correlationIds: e.correlationIds,
          evidenceRefs: e.evidenceRefs,
          originalRef: e.originalRef,
          engine: e.engine,
          dedupHash: dedupHash(e),
        })),
      )
      .onConflictDoNothing({ target: securityEvents.dedupHash })
      .returning({ id: securityEvents.id });
    const insertedIds = new Set(inserted.map((r) => r.id));
    report.accepted = insertedIds.size;
    report.duplicates = events.length - insertedIds.size;
    this.metrics.eventsIngested.inc(
      { sensor: source.sensorName, product: 'suricata' },
      report.accepted,
    );
    this.metrics.eventsDuplicate.inc(report.duplicates);

    const fresh = events.filter((e) => insertedIds.has(e.eventId));
    const latest = fresh.reduce<number>((m, e) => Math.max(m, Date.parse(e.eventTime)), 0);
    if (latest > 0) {
      report.maxEventLagSeconds = Math.max(0, (ingestTime.getTime() - latest) / 1000);
      this.metrics.ingestLag.set({ sensor: source.sensorName }, report.maxEventLagSeconds);
      await this.db
        .update(sensors)
        .set({
          lastEventAt: sql`greatest(coalesce(${sensors.lastEventAt}, 'epoch'::timestamptz), ${new Date(latest).toISOString()}::timestamptz)`,
        })
        .where(eq(sensors.id, source.sensorId));
    }

    // Alert queue: one open alert per (sensor, rule, src, dst); repeats bump the counter.
    const detections = fresh.filter((e) => e.category === 'detection' && e.ruleId);
    if (detections.length) {
      const assetIds = [
        ...new Set(
          detections.flatMap((e) => [e.srcAssetId, e.dstAssetId]).filter((x): x is string => !!x),
        ),
      ];
      const crit = new Map<string, (typeof assets.$inferSelect)['criticality']>();
      if (assetIds.length)
        for (const a of await this.db
          .select({ id: assets.id, criticality: assets.criticality })
          .from(assets)
          .where(inArray(assets.id, assetIds)))
          crit.set(a.id, a.criticality);
      const ruleIds = await resolveRuleIds(
        this.db,
        detections.map((e) => e.ruleId!),
      );
      for (const e of detections) {
        const key = `${source.sensorId}:${e.ruleId}:${e.srcIp ?? '-'}:${e.dstIp ?? '-'}`;
        const assetId = e.dstAssetId ?? e.srcAssetId ?? null;
        const priority = computeAlertPriority({
          severity: e.severity,
          confidence: e.confidence,
          assetCriticality: assetId ? (crit.get(assetId) ?? 'unclassified') : 'unclassified',
        }).score;
        const eventTime = new Date(e.eventTime);
        const [open] = await this.db
          .select({ id: alerts.id, lastSeenAt: alerts.lastSeenAt, firstSeenAt: alerts.firstSeenAt })
          .from(alerts)
          .where(
            and(eq(alerts.dedupKey, key), notInArray(alerts.status, [...CLOSED_ALERT_STATUSES])),
          )
          .limit(1);
        if (open) {
          await this.db
            .update(alerts)
            .set({
              occurrenceCount: sql`${alerts.occurrenceCount} + 1`,
              lastSeenAt: eventTime > open.lastSeenAt ? eventTime : open.lastSeenAt,
              firstSeenAt: eventTime < open.firstSeenAt ? eventTime : open.firstSeenAt,
              lastEventId: e.eventId,
              priorityScore: sql`greatest(${alerts.priorityScore}, ${priority})`,
              updatedAt: ingestTime,
            })
            .where(eq(alerts.id, open.id));
          report.alertsUpdated++;
          this.publish({
            kind: 'updated',
            alertId: open.id,
            severity: e.severity,
            title: alertTitleFor(e),
            at: ingestTime.toISOString(),
          });
        } else {
          const [created] = await this.db
            .insert(alerts)
            .values({
              title: alertTitleFor(e),
              status: 'new',
              severity: e.severity,
              confidence: e.confidence,
              priorityScore: priority,
              ruleId: ruleIds.get(e.ruleId!) ?? null,
              ruleRef: e.ruleId,
              sourceProduct: product,
              sourceSensorId: source.sensorId,
              assetId,
              srcIp: e.srcIp,
              dstIp: e.dstIp,
              dedupKey: key,
              occurrenceCount: 1,
              firstSeenAt: eventTime,
              lastSeenAt: eventTime,
              lastEventId: e.eventId,
            })
            .returning({ id: alerts.id });
          report.alertsCreated++;
          this.publish({
            kind: 'created',
            alertId: created!.id,
            severity: e.severity,
            title: alertTitleFor(e),
            at: ingestTime.toISOString(),
          });
          this.metrics.alertsCreated.inc({ severity: e.severity });
        }
      }
    }
    // Threat-intel: every accepted event is compared with the active indicator index; hits raise
    // or bump their own alerts and are recorded per (indicator, event, field).
    if (this.threatIntel && fresh.length) {
      const ti = await this.threatIntel.matchEvents(
        fresh.map((e) => ({
          eventId: e.eventId,
          eventTime: new Date(e.eventTime),
          sourceProduct: e.sourceProduct,
          sourceSensorId: e.sourceSensorId,
          srcIp: e.srcIp,
          dstIp: e.dstIp,
          srcAssetId: e.srcAssetId,
          dstAssetId: e.dstAssetId,
          severity: e.severity,
          engine: e.engine,
        })),
        ingestTime,
      );
      report.indicatorMatches = ti.matches;
      report.alertsCreated += ti.alertsCreated;
      report.alertsUpdated += ti.alertsUpdated;
    }
    return report;
  }

  private publish(ev: AlertStreamEvent): void {
    try {
      this.bus.publish(ev);
    } catch {
      /* a failing subscriber must never fail ingestion */
    }
  }
}
