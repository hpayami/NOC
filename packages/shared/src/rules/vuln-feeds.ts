import type { VulnerabilityFeedFormat } from '../entities/vulnerabilities';

const CVE = /^CVE-\d{4}-\d{4,}$/;

/** What an import contributes for one CVE; null fields mean "this feed does not say". */
export interface VulnerabilityInput {
  cveId: string;
  summary: string | null;
  cvssBaseScore: number | null;
  cvssVector: string | null;
  cvssVersion: string | null;
  cwe: string[];
  publishedAt: string | null;
  lastModifiedAt: string | null;
  knownExploited: boolean | null;
  kevAddedAt: string | null;
  kevDueAt: string | null;
}

export interface FeedParseResult {
  records: VulnerabilityInput[];
  errors: string[];
}

/**
 * NVD/KEV emit ISO-8601 timestamps that carry no offset but always mean UTC. `new Date` reads
 * such a value as *local* time, so on any host not running UTC the parsed instant drifts by the
 * host offset. A whole-string match (no trailing offset/Z at all) is therefore treated as UTC.
 */
const OFFSETLESS_STAMP = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/;

const iso = (v: unknown): string | null => {
  if (typeof v !== 'string' || !v) return null;
  const t = v.trim();
  const d = new Date(OFFSETLESS_STAMP.test(t) ? `${t}Z` : v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};
const num = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 10 ? v : null;
const str = (v: unknown, max: number): string | null =>
  typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null;

function empty(cveId: string): VulnerabilityInput {
  return {
    cveId,
    summary: null,
    cvssBaseScore: null,
    cvssVector: null,
    cvssVersion: null,
    cwe: [],
    publishedAt: null,
    lastModifiedAt: null,
    knownExploited: null,
    kevAddedAt: null,
    kevDueAt: null,
  };
}

/** NVD API 2.0 document: `{ vulnerabilities: [{ cve: {...} }] }`. */
function parseNvd(doc: unknown, out: FeedParseResult): void {
  const list = (doc as { vulnerabilities?: unknown[] })?.vulnerabilities;
  if (!Array.isArray(list)) {
    out.errors.push('nvd_2: document has no `vulnerabilities` array');
    return;
  }
  list.forEach((item, i) => {
    const cve = (item as { cve?: Record<string, unknown> })?.cve;
    const id = str(cve?.['id'], 32);
    if (!cve || !id || !CVE.test(id)) {
      out.errors.push(`nvd_2[${i}]: missing or malformed cve.id`);
      return;
    }
    const rec = empty(id);
    const descs = cve['descriptions'];
    if (Array.isArray(descs)) {
      const en = descs.find((d) => (d as { lang?: string })?.lang === 'en') ?? descs[0];
      rec.summary = str((en as { value?: unknown })?.value, 4096);
    }
    const metrics = cve['metrics'] as Record<string, unknown[]> | undefined;
    for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
      const m = metrics?.[key];
      if (Array.isArray(m) && m.length) {
        const primary = m.find((x) => (x as { type?: string })?.type === 'Primary') ?? m[0];
        const data = (primary as { cvssData?: Record<string, unknown> })?.cvssData;
        rec.cvssBaseScore = num(data?.['baseScore']);
        rec.cvssVector = str(data?.['vectorString'], 256);
        rec.cvssVersion = str(data?.['version'], 8);
        break;
      }
    }
    const weaknesses = cve['weaknesses'];
    if (Array.isArray(weaknesses))
      rec.cwe = [
        ...new Set(
          weaknesses
            .flatMap((w) => ((w as { description?: unknown[] })?.description ?? []) as unknown[])
            .map((d) => str((d as { value?: unknown })?.value, 16))
            .filter((v): v is string => !!v && /^CWE-\d+$/.test(v)),
        ),
      ].slice(0, 16);
    rec.publishedAt = iso(cve['published']);
    rec.lastModifiedAt = iso(cve['lastModified']);
    out.records.push(rec);
  });
}

/** CISA Known Exploited Vulnerabilities catalogue: `{ vulnerabilities: [{ cveID, dateAdded, dueDate, ... }] }`. */
function parseKev(doc: unknown, out: FeedParseResult): void {
  const list = (doc as { vulnerabilities?: unknown[] })?.vulnerabilities;
  if (!Array.isArray(list)) {
    out.errors.push('cisa_kev: document has no `vulnerabilities` array');
    return;
  }
  list.forEach((item, i) => {
    const v = item as Record<string, unknown>;
    const id = str(v['cveID'], 32);
    if (!id || !CVE.test(id)) {
      out.errors.push(`cisa_kev[${i}]: missing or malformed cveID`);
      return;
    }
    const rec = empty(id);
    rec.knownExploited = true;
    rec.kevAddedAt = iso(v['dateAdded']);
    rec.kevDueAt = iso(v['dueDate']);
    const name = str(v['vulnerabilityName'], 256);
    const desc = str(v['shortDescription'], 3800);
    rec.summary = desc ? (name ? `${name}: ${desc}` : desc) : name;
    out.records.push(rec);
  });
}

/** Platform-native: an array of partial VulnerabilityInput objects (used by connectors and tests). */
function parseNative(doc: unknown, out: FeedParseResult): void {
  if (!Array.isArray(doc)) {
    out.errors.push('noc: document must be a JSON array');
    return;
  }
  doc.forEach((item, i) => {
    const v = item as Record<string, unknown>;
    const id = str(v['cveId'], 32);
    if (!id || !CVE.test(id)) {
      out.errors.push(`noc[${i}]: missing or malformed cveId`);
      return;
    }
    const rec = empty(id);
    rec.summary = str(v['summary'], 4096);
    rec.cvssBaseScore = num(v['cvssBaseScore']);
    rec.cvssVector = str(v['cvssVector'], 256);
    rec.cvssVersion = str(v['cvssVersion'], 8);
    rec.cwe = Array.isArray(v['cwe'])
      ? (v['cwe'] as unknown[])
          .map((c) => str(c, 16))
          .filter((c): c is string => !!c && /^CWE-\d+$/.test(c))
          .slice(0, 16)
      : [];
    rec.publishedAt = iso(v['publishedAt']);
    rec.lastModifiedAt = iso(v['lastModifiedAt']);
    rec.knownExploited =
      typeof v['knownExploited'] === 'boolean' ? (v['knownExploited'] as boolean) : null;
    rec.kevAddedAt = iso(v['kevAddedAt']);
    rec.kevDueAt = iso(v['kevDueAt']);
    out.records.push(rec);
  });
}

/** Parses a feed document; malformed entries become errors, never silently dropped. */
export function parseVulnerabilityFeed(
  format: VulnerabilityFeedFormat,
  content: string,
): FeedParseResult {
  const out: FeedParseResult = { records: [], errors: [] };
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch (err) {
    out.errors.push(
      `invalid JSON: ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`,
    );
    return out;
  }
  if (format === 'nvd_2') parseNvd(doc, out);
  else if (format === 'cisa_kev') parseKev(doc, out);
  else parseNative(doc, out);
  // Last occurrence of a CVE wins inside one document, keeping order deterministic.
  const byId = new Map<string, VulnerabilityInput>();
  for (const r of out.records) byId.set(r.cveId, r);
  out.records = [...byId.values()];
  return out;
}
