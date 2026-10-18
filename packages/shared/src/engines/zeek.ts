import { NormalizedEvent } from '../entities/secops';
import type { EventCategory, Severity } from '../enums';

export type ZeekNormalizeResult =
  { ok: true; event: NormalizedEvent } | { ok: false; reason: string };

/** Zeek log streams the platform understands (the `_path` of json-streaming / the log file name). */
export const ZEEK_PATHS = [
  'conn',
  'dns',
  'ssl',
  'http',
  'ssh',
  'notice',
  'weird',
  'files',
  'x509',
  'smb_mapping',
  'kerberos',
  'ntlm',
  'rdp',
  'dhcp',
] as const;
export type ZeekPath = (typeof ZEEK_PATHS)[number];

const CATEGORY: Record<ZeekPath, EventCategory> = {
  conn: 'network',
  dns: 'dns',
  ssl: 'tls',
  http: 'http',
  ssh: 'network',
  notice: 'detection',
  weird: 'network',
  files: 'file',
  x509: 'tls',
  smb_mapping: 'network',
  kerberos: 'authentication',
  ntlm: 'authentication',
  rdp: 'network',
  dhcp: 'network',
};

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, max = 256) => (typeof v === 'string' ? v.slice(0, max) : undefined);
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const bool = (v: unknown) => (typeof v === 'boolean' ? v : undefined);
const strs = (v: unknown, max = 8) =>
  Array.isArray(v)
    ? v
        .filter((x): x is string => typeof x === 'string')
        .slice(0, max)
        .map((x) => x.slice(0, 256))
    : undefined;

/** Zeek `ts` is epoch seconds (float) by default, or ISO-8601 when `JSON::TS_ISO8601` is set. */
export function parseZeekTimestamp(ts: unknown): string | null {
  if (typeof ts === 'number' && Number.isFinite(ts) && ts > 0)
    return new Date(Math.round(ts * 1000)).toISOString();
  if (typeof ts === 'string') {
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  return null;
}

/** Notice severity by `note`: positive detections outrank protocol oddities. */
export function noticeSeverity(note: string | undefined): Severity {
  if (!note) return 'low';
  if (note.startsWith('Intel::')) return 'high';
  if (
    note.startsWith('Scan::') ||
    note === 'SSH::Password_Guessing' ||
    note.startsWith('HTTP::SQL_Injection') ||
    note.startsWith('Signatures::')
  )
    return 'medium';
  if (note.startsWith('Weird::') || note.startsWith('Conn::') || note.startsWith('SSL::'))
    return 'low';
  return 'low';
}

function engineFields(path: ZeekPath, r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {
    flow_id: str(r.uid, 64),
    community_id: str(r.community_id, 128),
    zeek_path: path,
  };
  switch (path) {
    case 'conn':
      out.conn = {
        service: str(r.service, 32),
        duration: num(r.duration),
        orig_bytes: num(r.orig_bytes),
        resp_bytes: num(r.resp_bytes),
        conn_state: str(r.conn_state, 16),
        history: str(r.history, 64),
        missed_bytes: num(r.missed_bytes),
        orig_pkts: num(r.orig_pkts),
        resp_pkts: num(r.resp_pkts),
        local_orig: bool(r.local_orig),
        local_resp: bool(r.local_resp),
      };
      break;
    case 'dns':
      out.dns = {
        query: str(r.query, 512),
        qtype_name: str(r.qtype_name, 16),
        rcode_name: str(r.rcode_name, 16),
        answers: strs(r.answers),
        rejected: bool(r.rejected),
        AA: bool(r.AA),
      };
      break;
    case 'ssl':
      out.tls = {
        sni: str(r.server_name, 256),
        version: str(r.version, 16),
        cipher: str(r.cipher, 128),
        ja3: str(r.ja3, 64) ? { hash: str(r.ja3, 64) } : undefined,
        ja3s: str(r.ja3s, 64) ? { hash: str(r.ja3s, 64) } : undefined,
        validation_status: str(r.validation_status, 128),
        subject: str(r.subject, 256),
        issuer: str(r.issuer, 256),
        established: bool(r.established),
      };
      break;
    case 'http':
      out.http = {
        hostname: str(r.host, 256),
        url: str(r.uri, 1024),
        http_method: str(r.method, 16),
        status: num(r.status_code),
        http_user_agent: str(r.user_agent, 256),
        resp_mime_types: strs(r.resp_mime_types, 4),
        request_body_len: num(r.request_body_len),
        response_body_len: num(r.response_body_len),
      };
      break;
    case 'ssh':
      out.ssh = {
        auth_success: bool(r.auth_success),
        auth_attempts: num(r.auth_attempts),
        client: str(r.client, 128),
        server: str(r.server, 128),
        direction: str(r.direction, 16),
      };
      break;
    case 'notice':
      out.notice = {
        note: str(r.note, 128),
        msg: str(r.msg, 512),
        sub: str(r.sub, 512),
        actions: strs(r.actions, 8),
        src: str(r.src, 64),
        dst: str(r.dst, 64),
        p: num(r.p),
        n: num(r.n),
      };
      break;
    case 'weird':
      out.weird = { name: str(r.name, 128), addl: str(r.addl, 256), notice: bool(r.notice) };
      break;
    case 'files':
      out.fileinfo = {
        fuid: str(r.fuid, 64),
        filename: str(r.filename, 512),
        mime_type: str(r.mime_type, 128),
        size: num(r.total_bytes),
        md5: str(r.md5, 32),
        sha1: str(r.sha1, 40),
        sha256: str(r.sha256, 64),
        source: str(r.source, 32),
      };
      break;
    case 'x509':
      out.x509 = {
        subject: str(
          (r['certificate.subject'] as unknown) ??
            (isObj(r.certificate) ? r.certificate.subject : undefined),
          256,
        ),
        issuer: str(
          (r['certificate.issuer'] as unknown) ??
            (isObj(r.certificate) ? r.certificate.issuer : undefined),
          256,
        ),
        not_valid_after:
          num(r['certificate.not_valid_after']) ??
          (isObj(r.certificate) ? num(r.certificate.not_valid_after) : undefined),
      };
      break;
    default:
      break;
  }
  return JSON.parse(JSON.stringify(out)) as Record<string, unknown>;
}

/**
 * Maps one Zeek JSON log record to the normalized envelope. The stream is taken from the record's
 * `_path` (json-streaming) or the caller-provided default. Zeek notices become detections
 * (`ruleId = zeek:<note>`); everything else is protocol telemetry with high confidence.
 */
export function normalizeZeekRecord(
  raw: unknown,
  ctx: {
    sensorId: string | null;
    eventId: string;
    ingestTime: string;
    defaultPath?: string | undefined;
  },
): ZeekNormalizeResult {
  if (!isObj(raw)) return { ok: false, reason: 'not_an_object' };
  const path = (str(raw._path, 32) ?? ctx.defaultPath) as ZeekPath | undefined;
  if (!path) return { ok: false, reason: 'missing_path' };
  if (!(ZEEK_PATHS as readonly string[]).includes(path))
    return { ok: false, reason: `unsupported_path:${path}` };
  const eventTime = parseZeekTimestamp(raw.ts);
  if (!eventTime) return { ok: false, reason: 'invalid_timestamp' };

  const id = isObj(raw.id) ? raw.id : raw;
  const srcIp =
    str(id['orig_h'] ?? raw['id.orig_h'] ?? (path === 'notice' ? raw.src : undefined), 64) ?? null;
  const dstIp =
    str(id['resp_h'] ?? raw['id.resp_h'] ?? (path === 'notice' ? raw.dst : undefined), 64) ?? null;
  const srcPort = num(id['orig_p'] ?? raw['id.orig_p']) ?? null;
  const dstPort =
    num(id['resp_p'] ?? raw['id.resp_p'] ?? (path === 'notice' ? raw.p : undefined)) ?? null;
  const note = path === 'notice' ? str(raw.note, 128) : undefined;
  const community = str(raw.community_id, 128);
  const uid = str(raw.uid, 64);

  const candidate = {
    schemaVersion: '1.0' as const,
    eventId: ctx.eventId,
    eventTime,
    ingestTime: ctx.ingestTime,
    sourceProduct: 'zeek' as const,
    sourceSensorId: ctx.sensorId,
    category: CATEGORY[path],
    type: path,
    severity:
      path === 'notice'
        ? noticeSeverity(note)
        : path === 'weird'
          ? ('low' as const)
          : ('info' as const),
    confidence: path === 'notice' ? ('medium' as const) : ('high' as const),
    srcAssetId: null,
    dstAssetId: null,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    protocol: str(raw.proto, 32)?.toLowerCase() ?? null,
    ruleId: note ? `zeek:${note}` : null,
    threatClassification: [],
    incidentId: null,
    evidenceRefs: [],
    correlationIds: [
      ...(uid ? [`zeek:${uid}`] : []),
      ...(community ? [`community:${community}`] : []),
    ],
    originalRef: null,
    engine: engineFields(path, raw),
  };
  const parsed = NormalizedEvent.safeParse(candidate);
  if (!parsed.success)
    return {
      ok: false,
      reason: `schema:${parsed.error.issues[0]?.path.join('.') ?? '?'}:${parsed.error.issues[0]?.message ?? 'invalid'}`,
    };
  return { ok: true, event: parsed.data };
}
