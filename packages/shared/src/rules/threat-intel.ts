import ipaddr from 'ipaddr.js';
import type { Severity } from '../enums';
import type { IndicatorFeedFormat, IndicatorType, MatchedField } from '../entities/threat-intel';
import { IndicatorTypeValues } from '../entities/threat-intel';
import { SeverityValues } from '../enums';

/** One indicator as a feed contributes it; the platform decides identity by (type, value). */
export interface IndicatorInput {
  type: IndicatorType;
  value: string;
  source: string;
  /** null = the feed did not say; defaults apply on insert and never overwrite on update. */
  confidence: number | null;
  severity: Severity | null;
  tags: string[];
  description: string | null;
  expiresAt: string | null;
  revoked: boolean;
}

export interface IndicatorFeedResult {
  records: IndicatorInput[];
  errors: string[];
}

const HEX = { sha256: /^[0-9a-f]{64}$/, sha1: /^[0-9a-f]{40}$/, md5: /^[0-9a-f]{32}$/ } as const;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;

/**
 * Canonical form of an indicator value, or null when it is not a valid value of that type.
 * IPs are normalised through ipaddr (so `::1` and `0:0::1` are one indicator), domains and
 * hashes lower-cased, URLs stripped of scheme and trailing slash (matching ignores both).
 */
export function normalizeIndicatorValue(type: IndicatorType, raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  switch (type) {
    case 'ipv4':
      return ipaddr.IPv4.isValidFourPartDecimal(v) ? ipaddr.IPv4.parse(v).toString() : null;
    case 'ipv6':
      if (!ipaddr.IPv6.isValid(v)) return null;
      return ipaddr.IPv6.parse(v).toNormalizedString();
    case 'cidr': {
      if (!ipaddr.isValidCIDR(v)) return null;
      const [addr, bits] = ipaddr.parseCIDR(v);
      return `${addr.kind() === 'ipv6' ? (addr as ipaddr.IPv6).toNormalizedString() : addr.toString()}/${bits}`;
    }
    case 'domain': {
      const d = v.toLowerCase().replace(/\.$/, '');
      return DOMAIN.test(d) ? d : null;
    }
    case 'url':
      return normalizeUrl(v);
    case 'sha256':
    case 'sha1':
    case 'md5': {
      const h = v.toLowerCase();
      return HEX[type].test(h) ? h : null;
    }
  }
}

/** Scheme-less, host lower-cased, no trailing slash; the path keeps its case. */
export function normalizeUrl(raw: string): string | null {
  const v = raw.trim();
  if (!v || v.length > 2048 || /\s/.test(v)) return null;
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/?#]+)([^\s]*)$/i.exec(v);
  if (!m) return null;
  const host = m[1]!.toLowerCase();
  if (!host || /[^a-z0-9.:[\]_-]/.test(host)) return null;
  const rest = (m[2] ?? '').replace(/\/$/, '');
  return `${host}${rest}`;
}

const sev = (v: unknown, fallback: Severity): Severity =>
  typeof v === 'string' && (SeverityValues as readonly string[]).includes(v.toLowerCase())
    ? (v.toLowerCase() as Severity)
    : fallback;
const conf = (v: unknown): number => {
  const n = typeof v === 'string' ? Number(v) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : 50;
};
const iso = (v: unknown): string | null => {
  if (typeof v !== 'string' || !v.trim()) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};
const tagsOf = (v: unknown): string[] =>
  (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[;|]/) : [])
    .map((t) => String(t).trim().slice(0, 64))
    .filter(Boolean)
    .slice(0, 32);
const str = (v: unknown, max: number): string | null =>
  typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null;

const MAX_RECORDS = 200_000;

interface ParseOpts {
  source: string;
  /** Applied by the importer to new indicators whose feed states no severity. */
  defaultSeverity: Severity;
}

function build(
  errors: string[],
  idx: string,
  type: unknown,
  value: unknown,
  rest: Partial<Omit<IndicatorInput, 'type' | 'value'>>,
  opts: ParseOpts,
): IndicatorInput | null {
  const t = typeof type === 'string' ? type.toLowerCase().trim() : '';
  const typeNorm = t === 'ip' || t === 'ipv4-addr' ? 'ipv4' : t === 'ipv6-addr' ? 'ipv6' : t;
  if (!(IndicatorTypeValues as readonly string[]).includes(typeNorm)) {
    errors.push(`${idx}: unknown indicator type ${JSON.stringify(type ?? null)}`);
    return null;
  }
  let it = typeNorm as IndicatorType;
  const raw = typeof value === 'string' ? value : '';
  // A feed may label a CIDR as an address; keep the semantics, fix the type.
  if ((it === 'ipv4' || it === 'ipv6') && raw.includes('/')) it = 'cidr';
  const v = normalizeIndicatorValue(it, raw);
  if (v === null) {
    errors.push(`${idx}: invalid ${it} value ${JSON.stringify(raw.slice(0, 64))}`);
    return null;
  }
  return {
    type: it,
    value: v,
    source: rest.source ?? opts.source,
    confidence: rest.confidence ?? null,
    severity: rest.severity ?? null,
    tags: rest.tags ?? [],
    description: rest.description ?? null,
    expiresAt: rest.expiresAt ?? null,
    revoked: rest.revoked ?? false,
  };
}

/** Platform JSON: `{ indicators: [...] }` or a bare array of `{ type, value, ... }`. */
function parseNoc(content: string, opts: ParseOpts): IndicatorFeedResult {
  const errors: string[] = [];
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return { records: [], errors: ['invalid JSON'] };
  }
  const arr = Array.isArray(doc)
    ? doc
    : doc && typeof doc === 'object' && Array.isArray((doc as { indicators?: unknown }).indicators)
      ? (doc as { indicators: unknown[] }).indicators
      : null;
  if (!arr) return { records: [], errors: ['expected { indicators: [...] } or an array'] };
  const records: IndicatorInput[] = [];
  for (const [i, o] of arr.slice(0, MAX_RECORDS).entries()) {
    if (!o || typeof o !== 'object') {
      errors.push(`#${i}: not an object`);
      continue;
    }
    const r = o as Record<string, unknown>;
    const rec = build(
      errors,
      `#${i}`,
      r.type,
      r.value,
      {
        confidence: r.confidence === undefined ? undefined : conf(r.confidence),
        severity: r.severity === undefined ? undefined : sev(r.severity, opts.defaultSeverity),
        tags: tagsOf(r.tags),
        description: str(r.description, 1024),
        expiresAt: iso(r.expiresAt ?? r.expires_at),
        revoked: r.revoked === true,
      },
      opts,
    );
    if (rec) records.push(rec);
  }
  return { records, errors };
}

/** Minimal RFC 4180 line split: quoted fields may contain commas and doubled quotes. */
export function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (q) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

/** CSV with a header row; `type` and `value` required, other columns optional, `#` comments. */
function parseCsv(content: string, opts: ParseOpts): IndicatorFeedResult {
  const errors: string[] = [];
  // Real file line numbers in errors: blanks and `#` comments are skipped, not renumbered.
  const lines = content
    .split(/\r?\n/)
    .map((text, i) => ({ no: i + 1, text }))
    .filter((l) => l.text.trim() && !l.text.trimStart().startsWith('#'));
  if (lines.length === 0) return { records: [], errors: ['empty CSV'] };
  const header = splitCsvLine(lines[0]!.text).map((h) => h.toLowerCase().replace(/[\s-]+/g, '_'));
  const col = (name: string) => header.indexOf(name);
  if (col('type') < 0 || col('value') < 0)
    return { records: [], errors: ['CSV header must include type and value'] };
  const records: IndicatorInput[] = [];
  for (const line of lines.slice(1, MAX_RECORDS + 1)) {
    const f = splitCsvLine(line.text);
    const at = (name: string) => (col(name) >= 0 ? f[col(name)] : undefined);
    const rec = build(
      errors,
      `line ${line.no}`,
      at('type'),
      at('value'),
      {
        source: str(at('source'), 256) ?? undefined,
        confidence: at('confidence') ? conf(at('confidence')) : undefined,
        severity: at('severity') ? sev(at('severity'), opts.defaultSeverity) : undefined,
        tags: tagsOf(at('tags')),
        description: str(at('description'), 1024),
        expiresAt: iso(at('expires_at') ?? at('valid_until')),
        revoked: /^(true|1|yes)$/i.test(at('revoked') ?? ''),
      },
      opts,
    );
    if (rec) records.push(rec);
  }
  return { records, errors };
}

const STIX_SIMPLE =
  /^\[\s*([a-z0-9-]+):((?:[a-z0-9_]+)(?:\.(?:'[^']+'|[A-Za-z0-9_-]+))*)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]$/i;
const STIX_TYPES: Record<string, IndicatorType> = {
  'ipv4-addr:value': 'ipv4',
  'ipv6-addr:value': 'ipv6',
  'domain-name:value': 'domain',
  'url:value': 'url',
  "file:hashes.'sha-256'": 'sha256',
  'file:hashes.sha-256': 'sha256',
  'file:hashes.sha256': 'sha256',
  "file:hashes.'sha-1'": 'sha1',
  'file:hashes.sha-1': 'sha1',
  'file:hashes.sha1': 'sha1',
  'file:hashes.md5': 'md5',
  "file:hashes.'md5'": 'md5',
};

/** Parses one simple STIX comparison; compound patterns are refused (never half-interpreted). */
export function parseStixPattern(pattern: string): { type: IndicatorType; value: string } | null {
  const m = STIX_SIMPLE.exec(pattern.trim());
  if (!m) return null;
  const key = `${m[1]!.toLowerCase()}:${m[2]!.toLowerCase()}`;
  const type = STIX_TYPES[key];
  if (!type) return null;
  return { type, value: m[3]!.replace(/\\(['\\])/g, '$1') };
}

/** STIX 2.1 bundle (or array of objects): `indicator` objects with a single-comparison pattern. */
function parseStix(content: string, opts: ParseOpts): IndicatorFeedResult {
  const errors: string[] = [];
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return { records: [], errors: ['invalid JSON'] };
  }
  const objects = Array.isArray(doc)
    ? doc
    : doc && typeof doc === 'object' && Array.isArray((doc as { objects?: unknown }).objects)
      ? (doc as { objects: unknown[] }).objects
      : null;
  if (!objects) return { records: [], errors: ['expected a STIX bundle with objects[]'] };
  const names = new Map<string, string>();
  for (const o of objects)
    if (o && typeof o === 'object') {
      const r = o as Record<string, unknown>;
      if (typeof r.id === 'string' && typeof r.name === 'string' && r.type === 'identity')
        names.set(r.id, r.name.slice(0, 256));
    }
  const records: IndicatorInput[] = [];
  let seen = 0;
  for (const o of objects.slice(0, MAX_RECORDS)) {
    if (!o || typeof o !== 'object' || (o as { type?: unknown }).type !== 'indicator') continue;
    seen++;
    const r = o as Record<string, unknown>;
    const idx = typeof r.id === 'string' ? r.id : `indicator #${seen}`;
    if (typeof r.pattern !== 'string') {
      errors.push(`${idx}: no pattern`);
      continue;
    }
    if (r.pattern_type !== undefined && r.pattern_type !== 'stix') {
      errors.push(`${idx}: unsupported pattern_type ${String(r.pattern_type)}`);
      continue;
    }
    const p = parseStixPattern(r.pattern);
    if (!p) {
      errors.push(
        `${idx}: unsupported pattern (only single comparisons on ip/domain/url/file hashes)`,
      );
      continue;
    }
    const labels = [
      ...tagsOf(r.labels),
      ...tagsOf(r.indicator_types),
      ...(Array.isArray(r.kill_chain_phases)
        ? r.kill_chain_phases
            .map((k) =>
              k && typeof k === 'object' ? (k as { phase_name?: unknown }).phase_name : null,
            )
            .filter((x): x is string => typeof x === 'string')
        : []),
    ].slice(0, 32);
    const sevLabel = labels.find((l) => /^(severity|priority):/i.test(l))?.split(':')[1];
    const createdBy =
      typeof r.created_by_ref === 'string' ? names.get(r.created_by_ref) : undefined;
    const rec = build(
      errors,
      idx,
      p.type,
      p.value,
      {
        source: createdBy ? `${opts.source} / ${createdBy}`.slice(0, 256) : undefined,
        confidence: r.confidence === undefined ? undefined : conf(r.confidence),
        severity: sevLabel ? sev(sevLabel, opts.defaultSeverity) : undefined,
        tags: labels,
        description: str(r.description, 1024) ?? str(r.name, 1024),
        expiresAt: iso(r.valid_until),
        revoked: r.revoked === true,
      },
      opts,
    );
    if (rec) records.push(rec);
  }
  if (seen === 0 && errors.length === 0) errors.push('bundle contains no indicator objects');
  return { records, errors };
}

export function parseIndicatorFeed(
  format: IndicatorFeedFormat,
  content: string,
  opts: ParseOpts,
): IndicatorFeedResult {
  const r =
    format === 'noc'
      ? parseNoc(content, opts)
      : format === 'csv'
        ? parseCsv(content, opts)
        : parseStix(content, opts);
  // Last occurrence of a (type, value) wins inside one feed, so a revocation after an assertion holds.
  const byKey = new Map<string, IndicatorInput>();
  for (const rec of r.records) byKey.set(`${rec.type}|${rec.value}`, rec);
  return { records: [...byKey.values()], errors: r.errors };
}

// ---- matching ----------------------------------------------------------------------------

/** The subset of an event the matcher reads; both normalised events and stored rows satisfy it. */
export interface MatchableEvent {
  srcIp: string | null;
  dstIp: string | null;
  engine: Record<string, unknown>;
}

export interface Observable {
  field: MatchedField;
  type: IndicatorType;
  value: string;
}

const strAt = (o: unknown, k: string): string | null => {
  if (!o || typeof o !== 'object') return null;
  const v = (o as Record<string, unknown>)[k];
  return typeof v === 'string' && v ? v : null;
};

/** Everything in an event an indicator could be compared against, in canonical form. */
export function extractObservables(e: MatchableEvent): Observable[] {
  const out: Observable[] = [];
  const ip = (field: MatchedField, v: string | null) => {
    if (!v) return;
    const n4 = normalizeIndicatorValue('ipv4', v);
    if (n4) return out.push({ field, type: 'ipv4', value: n4 });
    const n6 = normalizeIndicatorValue('ipv6', v);
    if (n6) out.push({ field, type: 'ipv6', value: n6 });
  };
  ip('src_ip', e.srcIp);
  ip('dst_ip', e.dstIp);
  const dom = (field: MatchedField, v: string | null) => {
    const d = v ? normalizeIndicatorValue('domain', v) : null;
    if (d) out.push({ field, type: 'domain', value: d });
  };
  dom('dns.query', strAt(e.engine.dns, 'rrname') ?? strAt(e.engine.dns, 'query'));
  dom('tls.sni', strAt(e.engine.tls, 'sni'));
  const host = strAt(e.engine.http, 'hostname');
  dom('http.hostname', host);
  const path = strAt(e.engine.http, 'url');
  if (host && path) {
    const u = normalizeUrl(`${host}${path.startsWith('/') ? '' : '/'}${path}`);
    if (u) out.push({ field: 'http.url', type: 'url', value: u });
  }
  const file = e.engine.fileinfo;
  for (const [field, type] of [
    ['file.sha256', 'sha256'],
    ['file.sha1', 'sha1'],
    ['file.md5', 'md5'],
  ] as const) {
    const h = strAt(file, type);
    const n = h ? normalizeIndicatorValue(type, h) : null;
    if (n) out.push({ field, type, value: n });
  }
  return out;
}

export interface IndexedIndicator {
  id: string;
  type: IndicatorType;
  value: string;
  source: string;
  severity: Severity;
  confidence: number;
}

export interface IndicatorHit {
  indicator: IndexedIndicator;
  field: MatchedField;
  value: string;
}

/**
 * In-memory index over active indicators. Exact sets for addresses, hashes and URLs; domains
 * match themselves and every subdomain (`evil.example` hits `cdn.evil.example`); CIDRs are
 * checked by containment. Built once per refresh, read on every ingest batch.
 */
export class IndicatorIndex {
  private readonly exact = new Map<string, IndexedIndicator[]>();
  private readonly cidrs: Array<{
    net: [ipaddr.IPv4 | ipaddr.IPv6, number];
    ind: IndexedIndicator;
  }> = [];
  readonly size: number;

  constructor(indicators: readonly IndexedIndicator[]) {
    for (const ind of indicators) {
      if (ind.type === 'cidr') {
        if (ipaddr.isValidCIDR(ind.value))
          this.cidrs.push({ net: ipaddr.parseCIDR(ind.value), ind });
        continue;
      }
      const k = `${ind.type}|${ind.value}`;
      const list = this.exact.get(k);
      if (list) list.push(ind);
      else this.exact.set(k, [ind]);
    }
    this.size = indicators.length;
  }

  match(observables: readonly Observable[]): IndicatorHit[] {
    const hits: IndicatorHit[] = [];
    const seen = new Set<string>();
    const add = (ind: IndexedIndicator, o: Observable) => {
      const k = `${ind.id}|${o.field}`;
      if (seen.has(k)) return;
      seen.add(k);
      hits.push({ indicator: ind, field: o.field, value: o.value });
    };
    for (const o of observables) {
      for (const ind of this.exact.get(`${o.type}|${o.value}`) ?? []) add(ind, o);
      if (o.type === 'domain') {
        const labels = o.value.split('.');
        for (let i = 1; i < labels.length - 1; i++)
          for (const ind of this.exact.get(`domain|${labels.slice(i).join('.')}`) ?? [])
            add(ind, o);
      }
      if ((o.type === 'ipv4' || o.type === 'ipv6') && this.cidrs.length) {
        const addr = ipaddr.parse(o.value);
        for (const c of this.cidrs)
          if (
            c.net[0].kind() === addr.kind() &&
            (addr as ipaddr.IPv4).match(c.net as [ipaddr.IPv4, number])
          )
            add(c.ind, o);
      }
    }
    return hits;
  }
}

export const indicatorAlertTitle = (h: IndicatorHit): string =>
  `Threat intel match: ${h.indicator.type} ${h.indicator.value} seen in ${h.field} (${h.indicator.source})`;
