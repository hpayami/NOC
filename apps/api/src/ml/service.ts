import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, gte, sql, type SQL } from 'drizzle-orm';
import type { Logger } from 'pino';
import {
  ML_FEATURE_SET_VERSION,
  ML_HISTORY_HOURS,
  type MlScoreRecord,
  type MlStatus,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { assetIdSiteCondition, assetSiteCondition } from '../middleware/scope';
import { assets, mlInferenceResults, securityEvents } from '../db/schema';

export interface Actor {
  userId: string;
  email: string;
  /** Site grants; null = unrestricted. Scoring is limited to assets inside the grants. */
  sites: readonly string[] | null;
  requestId: string | null;
  ip: string | null;
}

interface AnalysisScore {
  model_name: string;
  model_version: string;
  feature_set_version: string;
  score: number;
  advisory: true;
  explanation: Array<{
    feature: string;
    contribution: number;
    current: number;
    median: number;
    mad: number;
    z: number;
  }>;
}

const FEATURES = ['events', 'distinct_dst_ports', 'distinct_peers', 'detections'] as const;

const toRecord = (r: typeof mlInferenceResults.$inferSelect): MlScoreRecord => ({
  id: r.id,
  modelName: r.modelName,
  modelVersion: r.modelVersion,
  featureSetVersion: r.featureSetVersion,
  subjectType: r.subjectType,
  subjectId: r.subjectId,
  score: r.score,
  advisory: true,
  explanation: r.explanation,
  evidenceRefs: r.evidenceRefs as MlScoreRecord['evidenceRefs'],
  createdAt: r.createdAt.toISOString(),
  features: r.features,
  windowStart: r.windowStart.toISOString(),
  windowEnd: r.windowEnd.toISOString(),
});

/**
 * Bridge to the analysis service. Features are built here from the platform's own event store;
 * the service only scores. Results are stored for people to read — nothing acts on them.
 */
export class MlService {
  private probe: { at: number; status: Omit<MlStatus, 'resultCount'> } | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly logger: Logger,
    private readonly opts: {
      url: string;
      token: string | null;
      timeoutMs?: number;
      probeTtlMs?: number;
    },
  ) {}

  private headers(): Record<string, string> {
    return {
      'content-type': 'application/json',
      accept: 'application/json',
      ...(this.opts.token ? { 'x-internal-token': this.opts.token } : {}),
    };
  }

  private async call(path: string, init: RequestInit): Promise<Response> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 5000);
    try {
      return await fetch(`${this.opts.url}${path}`, {
        ...init,
        headers: this.headers(),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  /** Cached reachability + model register; the platform status page must not hammer the service. */
  async status(force = false): Promise<MlStatus> {
    const ttl = this.opts.probeTtlMs ?? 60_000;
    if (!force && this.probe && Date.now() - this.probe.at < ttl)
      return this.withCount(this.probe.status);
    const checkedAt = new Date().toISOString();
    let status: Omit<MlStatus, 'resultCount'>;
    try {
      const res = await this.call('/api/v1/analysis/status', { method: 'GET' });
      if (!res.ok) throw new Error(`analysis status HTTP ${res.status}`);
      const body = (await res.json()) as {
        advisory_only: true;
        external_model_apis_allowed: boolean;
        models: Array<{
          name: string;
          version: string;
          state: 'not_trained' | 'advisory' | 'disabled';
          kind: 'statistical_baseline' | 'learned';
          evaluation: string;
          min_history_points: number;
        }>;
      };
      status = {
        analysisUrl: this.opts.url,
        reachable: true,
        checkedAt,
        detail: null,
        advisoryOnly: true,
        externalModelApisAllowed: body.external_model_apis_allowed,
        models: body.models.map((m) => ({
          name: m.name,
          version: m.version,
          state: m.state,
          kind: m.kind,
          evaluation: m.evaluation,
          minHistoryPoints: m.min_history_points,
        })),
      };
    } catch (err) {
      status = {
        analysisUrl: this.opts.url,
        reachable: false,
        checkedAt,
        detail: (err instanceof Error ? err.message : String(err)).slice(0, 512),
        advisoryOnly: true,
        externalModelApisAllowed: null,
        models: [],
      };
    }
    this.probe = { at: Date.now(), status };
    return this.withCount(status);
  }

  private async withCount(status: Omit<MlStatus, 'resultCount'>): Promise<MlStatus> {
    const [r] = await this.db.select({ n: count() }).from(mlInferenceResults);
    return { ...status, resultCount: r?.n ?? 0 };
  }

  /**
   * Hourly feature series for one asset over the history window, from the event store. Buckets
   * with no events are explicit zeros so the baseline sees quiet hours as data, not as gaps.
   */
  async features(
    assetId: string,
    now: Date,
  ): Promise<{
    windowStart: Date;
    windowEnd: Date;
    history: Record<string, number[]>;
    current: Record<string, number>;
    eventCount: number;
  }> {
    const windowEnd = new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);
    const windowStart = new Date(windowEnd.getTime() - ML_HISTORY_HOURS * 3_600_000);
    const rows = await this.db
      .select({
        // Truncate in UTC and label the bucket as an explicit UTC instant. `date_trunc` alone
        // buckets in the *session* TimeZone and a bare `YYYY-MM-DD HH:MI:SS` label is re-read as
        // *local* time by `new Date`, so on any host set to anything but UTC the buckets drift off
        // the UTC hour the caller enumerates below and every lookup misses — the asset then looks
        // like it has no events and scoring is refused.
        bucket: sql<string>`to_char(date_trunc('hour', ${securityEvents.eventTime} at time zone 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
        events: count(),
        ports: sql<number>`count(distinct ${securityEvents.dstPort})`,
        peers: sql<number>`count(distinct case when ${securityEvents.srcAssetId} = ${assetId}::uuid then ${securityEvents.dstIp} else ${securityEvents.srcIp} end)`,
        detections: sql<number>`count(*) filter (where ${securityEvents.category} = 'detection')`,
      })
      .from(securityEvents)
      .where(
        and(
          gte(securityEvents.eventTime, windowStart),
          sql`(${securityEvents.srcAssetId} = ${assetId}::uuid or ${securityEvents.dstAssetId} = ${assetId}::uuid)`,
        ),
      )
      .groupBy(sql`1`);
    const byBucket = new Map(rows.map((r) => [new Date(r.bucket).getTime(), r]));
    const history: Record<string, number[]> = Object.fromEntries(FEATURES.map((f) => [f, []]));
    let eventCount = 0;
    for (let t = windowStart.getTime(); t < windowEnd.getTime(); t += 3_600_000) {
      const r = byBucket.get(t);
      history.events!.push(Number(r?.events ?? 0));
      history.distinct_dst_ports!.push(Number(r?.ports ?? 0));
      history.distinct_peers!.push(Number(r?.peers ?? 0));
      history.detections!.push(Number(r?.detections ?? 0));
      eventCount += Number(r?.events ?? 0);
    }
    const cur = byBucket.get(windowEnd.getTime());
    const current = {
      events: Number(cur?.events ?? 0),
      distinct_dst_ports: Number(cur?.ports ?? 0),
      distinct_peers: Number(cur?.peers ?? 0),
      detections: Number(cur?.detections ?? 0),
    };
    eventCount += current.events;
    return { windowStart, windowEnd, history, current, eventCount };
  }

  async scoreAsset(assetId: string, actor: Actor, now = new Date()): Promise<MlScoreRecord> {
    const [asset] = await this.db
      .select({ id: assets.id })
      .from(assets)
      .where(and(eq(assets.id, assetId), assetSiteCondition(actor.sites)))
      .limit(1);
    if (!asset) throw new HTTPException(404, { message: 'Asset not found' });
    const f = await this.features(assetId, now);
    if (f.eventCount === 0)
      throw new HTTPException(422, {
        message: 'Asset has no events in the history window; nothing to score',
      });
    let res: Response;
    try {
      res = await this.call('/api/v1/analysis/score', {
        method: 'POST',
        body: JSON.stringify({
          subject_type: 'asset',
          subject_id: assetId,
          feature_set_version: ML_FEATURE_SET_VERSION,
          features: FEATURES.map((name) => ({
            name,
            history: f.history[name],
            current: f.current[name],
          })),
        }),
      });
    } catch (err) {
      this.probe = null;
      throw new HTTPException(503, {
        message: `Analysis service unreachable: ${(err instanceof Error ? err.message : String(err)).slice(0, 200)}`,
      });
    }
    if (res.status === 422) {
      const body = (await res.json().catch(() => null)) as {
        detail?: { code?: string; message?: string };
      } | null;
      throw new HTTPException(422, {
        message: `Not scorable: ${body?.detail?.code ?? 'unscorable'}${body?.detail?.message ? ` (${body.detail.message})` : ''}`,
      });
    }
    if (!res.ok)
      throw new HTTPException(502, { message: `Analysis service returned HTTP ${res.status}` });
    const out = (await res.json()) as AnalysisScore;
    if (out.advisory !== true)
      throw new HTTPException(502, {
        message: 'Analysis service returned a non-advisory result; refused',
      });
    const [row] = await this.db
      .insert(mlInferenceResults)
      .values({
        modelName: out.model_name,
        modelVersion: out.model_version,
        featureSetVersion: out.feature_set_version,
        subjectType: 'asset',
        subjectId: assetId,
        score: out.score,
        explanation: out.explanation.map((e) => ({
          feature: e.feature,
          contribution: e.contribution,
        })),
        features: out.explanation.map((e) => ({
          feature: e.feature,
          current: e.current,
          median: e.median,
          mad: e.mad,
          z: e.z,
        })),
        evidenceRefs: [
          {
            kind: 'note',
            ref: `events:asset:${assetId}:${f.windowStart.toISOString()}..${f.windowEnd.toISOString()}`,
          },
        ],
        windowStart: f.windowStart,
        windowEnd: f.windowEnd,
        requestedBy: actor.userId,
      })
      .returning();
    await this.audit.record({
      actorId: actor.userId,
      actorLabel: actor.email,
      action: 'ml.score',
      outcome: 'success',
      targetType: 'asset',
      targetId: assetId,
      requestId: actor.requestId,
      sourceIp: actor.ip,
      metadata: {
        model: `${out.model_name}@${out.model_version}`,
        score: out.score,
        advisory: true,
      },
    });
    return toRecord(row!);
  }

  /** Scores every asset with events in the window; per-asset failures are reported, not hidden. */
  async scoreBatch(limit: number, actor: Actor, now = new Date()) {
    const since = new Date(now.getTime() - ML_HISTORY_HOURS * 3_600_000);
    const subjects = await this.db
      .select({
        id: sql<string>`coalesce(${securityEvents.srcAssetId}, ${securityEvents.dstAssetId})`,
      })
      .from(securityEvents)
      .where(
        and(
          gte(securityEvents.eventTime, since),
          sql`coalesce(${securityEvents.srcAssetId}, ${securityEvents.dstAssetId}) is not null`,
          assetIdSiteCondition(
            actor.sites,
            sql`coalesce(${securityEvents.srcAssetId}, ${securityEvents.dstAssetId})`,
          ),
        ),
      )
      .groupBy(sql`1`)
      .orderBy(desc(count()))
      .limit(limit);
    const results: MlScoreRecord[] = [];
    const skipped: Array<{ subjectId: string; reason: string }> = [];
    for (const s of subjects) {
      try {
        results.push(await this.scoreAsset(s.id, actor, now));
      } catch (err) {
        if (err instanceof HTTPException && err.status === 503) throw err;
        skipped.push({
          subjectId: s.id,
          reason: (err instanceof Error ? err.message : String(err)).slice(0, 256),
        });
      }
    }
    this.logger.info({ scored: results.length, skipped: skipped.length }, 'ml batch score');
    return { scored: results.length, skipped, results };
  }

  async list(conds: SQL[], limit: number): Promise<MlScoreRecord[]> {
    const rows = await this.db
      .select()
      .from(mlInferenceResults)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(mlInferenceResults.createdAt))
      .limit(limit);
    return rows.map(toRecord);
  }
}
