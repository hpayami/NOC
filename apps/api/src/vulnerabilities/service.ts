import { HTTPException } from 'hono/http-exception';
import { and, count, desc, eq, ilike, inArray, isNull, max, or, sql, type SQL } from 'drizzle-orm';
import {
  parseVulnerabilityFeed,
  type FindingRecord,
  type ImportVulnerabilitiesRequest,
  type ImportVulnerabilitiesResponse,
  type VulnerabilityCatalogStats,
  type VulnerabilityRecord,
} from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Db, DbTx } from '../db/client';
import { vulnerabilityCatalog, vulnerabilityFindings } from '../db/schema';

export interface Actor {
  userId: string;
  label: string;
  requestId: string | null;
  ip: string | null;
}

type Row = typeof vulnerabilityCatalog.$inferSelect;

export const toVulnerability = (r: Row): VulnerabilityRecord => ({
  cveId: r.cveId,
  summary: r.summary,
  cvssBaseScore: r.cvssBaseScore,
  cvssVector: r.cvssVector,
  cvssVersion: r.cvssVersion,
  cwe: r.cwe,
  publishedAt: r.publishedAt?.toISOString() ?? null,
  lastModifiedAt: r.lastModifiedAt?.toISOString() ?? null,
  knownExploited: r.knownExploited,
  kevAddedAt: r.kevAddedAt?.toISOString() ?? null,
  kevDueAt: r.kevDueAt?.toISOString() ?? null,
  sources: r.sources,
  importedAt: r.importedAt.toISOString(),
});

const BATCH = 500;

/**
 * Catalogue of CVEs the operator imported. Imports merge: a feed only overwrites the fields it
 * carries (KEV never clears a CVSS score; NVD never clears the exploited flag). Findings that
 * reference a catalogued CVE get their CVSS filled in when they have none.
 */
export class VulnerabilityService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
  ) {}

  async import(
    input: ImportVulnerabilitiesRequest,
    actor: Actor,
  ): Promise<ImportVulnerabilitiesResponse> {
    const parsed = parseVulnerabilityFeed(input.format, input.content);
    const res: ImportVulnerabilitiesResponse = {
      parsed: parsed.records.length,
      imported: 0,
      updated: 0,
      unchanged: 0,
      findingsEnriched: 0,
      errors: parsed.errors.slice(0, 20),
      errorCount: parsed.errors.length,
    };
    if (parsed.records.length === 0) {
      if (parsed.errors.length)
        throw new HTTPException(422, { message: `Feed rejected: ${parsed.errors[0]}` });
      return res;
    }
    const now = new Date();
    await this.db.transaction(async (tx) => {
      for (let i = 0; i < parsed.records.length; i += BATCH) {
        const slice = parsed.records.slice(i, i + BATCH);
        const ids = slice.map((r) => r.cveId);
        const existing = new Map(
          (
            await tx
              .select()
              .from(vulnerabilityCatalog)
              .where(inArray(vulnerabilityCatalog.cveId, ids))
          ).map((r) => [r.cveId, r]),
        );
        for (const r of slice) {
          const cur = existing.get(r.cveId);
          const next = {
            summary: r.summary ?? cur?.summary ?? '',
            cvssBaseScore: r.cvssBaseScore ?? cur?.cvssBaseScore ?? null,
            cvssVector: r.cvssVector ?? cur?.cvssVector ?? null,
            cvssVersion: r.cvssVersion ?? cur?.cvssVersion ?? null,
            cwe: r.cwe.length ? r.cwe : (cur?.cwe ?? []),
            publishedAt: r.publishedAt ? new Date(r.publishedAt) : (cur?.publishedAt ?? null),
            lastModifiedAt: r.lastModifiedAt
              ? new Date(r.lastModifiedAt)
              : (cur?.lastModifiedAt ?? null),
            knownExploited: r.knownExploited ?? cur?.knownExploited ?? false,
            kevAddedAt: r.kevAddedAt ? new Date(r.kevAddedAt) : (cur?.kevAddedAt ?? null),
            kevDueAt: r.kevDueAt ? new Date(r.kevDueAt) : (cur?.kevDueAt ?? null),
            sources: [...new Set([...(cur?.sources ?? []), input.format])],
          };
          if (!cur) {
            await tx
              .insert(vulnerabilityCatalog)
              .values({ cveId: r.cveId, ...next, importedAt: now });
            res.imported++;
            continue;
          }
          const same =
            cur.summary === next.summary &&
            cur.cvssBaseScore === next.cvssBaseScore &&
            cur.cvssVector === next.cvssVector &&
            cur.cvssVersion === next.cvssVersion &&
            JSON.stringify(cur.cwe) === JSON.stringify(next.cwe) &&
            (cur.publishedAt?.getTime() ?? null) === (next.publishedAt?.getTime() ?? null) &&
            (cur.lastModifiedAt?.getTime() ?? null) === (next.lastModifiedAt?.getTime() ?? null) &&
            cur.knownExploited === next.knownExploited &&
            (cur.kevAddedAt?.getTime() ?? null) === (next.kevAddedAt?.getTime() ?? null) &&
            (cur.kevDueAt?.getTime() ?? null) === (next.kevDueAt?.getTime() ?? null) &&
            JSON.stringify(cur.sources) === JSON.stringify(next.sources);
          if (same) {
            res.unchanged++;
            continue;
          }
          await tx
            .update(vulnerabilityCatalog)
            .set({ ...next, importedAt: now })
            .where(eq(vulnerabilityCatalog.cveId, r.cveId));
          res.updated++;
        }
      }
      res.findingsEnriched = await this.enrichFindings(
        tx,
        parsed.records.map((r) => r.cveId),
      );
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'vulnerabilities.import',
          outcome: 'success',
          targetType: 'vulnerability_catalog',
          targetId: null,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { format: input.format, ...res, errors: undefined },
        },
        tx,
      );
    });
    return res;
  }

  /** Fills CVSS on findings that reference a catalogued CVE and have none; never overwrites. */
  private async enrichFindings(tx: DbTx, cveIds: string[]): Promise<number> {
    if (cveIds.length === 0) return 0;
    const rows = await tx.execute(sql`
      update vulnerability_findings f
      set cvss_base_score = c.cvss_base_score,
          cvss_vector = coalesce(f.cvss_vector, c.cvss_vector),
          updated_at = now()
      from (
        select distinct on (cve_id) cve_id, cvss_base_score, cvss_vector
        from vulnerability_catalog
        where cve_id = any(${sql.raw(`ARRAY[${cveIds.map((c) => `'${c.replace(/'/g, "''")}'`).join(',')}]::text[]`)})
          and cvss_base_score is not null
      ) c
      where f.cvss_base_score is null and c.cve_id = any(f.cve)
      returning f.id
    `);
    return (rows as unknown as unknown[]).length;
  }

  /** Attaches catalogue entries to findings by CVE id (one query for the whole page). */
  async attach(findings: FindingRecord[]): Promise<FindingRecord[]> {
    const ids = [...new Set(findings.flatMap((f) => f.cve))];
    if (ids.length === 0) return findings;
    const rows = await this.db
      .select()
      .from(vulnerabilityCatalog)
      .where(inArray(vulnerabilityCatalog.cveId, ids));
    const byId = new Map(rows.map((r) => [r.cveId, toVulnerability(r)]));
    return findings.map((f) => ({
      ...f,
      vulnerabilities: f.cve
        .map((c) => byId.get(c))
        .filter((v): v is VulnerabilityRecord => !!v)
        .slice(0, 32),
    }));
  }

  async list(q: {
    q?: string;
    knownExploited?: boolean;
    limit: number;
  }): Promise<VulnerabilityRecord[]> {
    const conds: SQL[] = [];
    if (q.q) {
      const like = `%${q.q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
      conds.push(
        or(ilike(vulnerabilityCatalog.cveId, like), ilike(vulnerabilityCatalog.summary, like))!,
      );
    }
    if (q.knownExploited !== undefined)
      conds.push(eq(vulnerabilityCatalog.knownExploited, q.knownExploited));
    const rows = await this.db
      .select()
      .from(vulnerabilityCatalog)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(
        desc(vulnerabilityCatalog.knownExploited),
        desc(vulnerabilityCatalog.cvssBaseScore),
        vulnerabilityCatalog.cveId,
      )
      .limit(q.limit);
    return rows.map(toVulnerability);
  }

  async get(cveId: string): Promise<VulnerabilityRecord> {
    const [row] = await this.db
      .select()
      .from(vulnerabilityCatalog)
      .where(eq(vulnerabilityCatalog.cveId, cveId))
      .limit(1);
    if (!row) throw new HTTPException(404, { message: 'CVE not in the catalogue' });
    return toVulnerability(row);
  }

  async stats(): Promise<VulnerabilityCatalogStats> {
    const [r] = await this.db
      .select({
        total: count(),
        kev: sql<number>`count(*) filter (where ${vulnerabilityCatalog.knownExploited})::int`,
        withCvss: sql<number>`count(*) filter (where ${vulnerabilityCatalog.cvssBaseScore} is not null)::int`,
        last: max(vulnerabilityCatalog.importedAt),
      })
      .from(vulnerabilityCatalog);
    return {
      total: r?.total ?? 0,
      knownExploited: Number(r?.kev ?? 0),
      withCvss: Number(r?.withCvss ?? 0),
      lastImportAt: r?.last ? new Date(r.last).toISOString() : null,
    };
  }

  /** Findings that have CVEs but no catalogue entry at all: what the operator should import next. */
  async uncatalogued(limit = 50): Promise<string[]> {
    const rows = await this.db.execute(sql`
      select distinct c as cve from vulnerability_findings f, unnest(f.cve) as c
      where not exists (select 1 from vulnerability_catalog v where v.cve_id = c)
      order by c limit ${limit}
    `);
    return (rows as unknown as Array<{ cve: string }>).map((r) => r.cve);
  }
}

/** Drizzle helper kept for callers that filter findings by missing CVSS. */
export const findingsWithoutCvss = () => isNull(vulnerabilityFindings.cvssBaseScore);
