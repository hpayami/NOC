import { NormalizedEvent } from '../entities/secops';
import type { EventCategory, Severity } from '../enums';

export type EveNormalizeResult =
  { ok: true; event: NormalizedEvent } | { ok: false; reason: string };

const CATEGORY: Record<string, EventCategory> = {
  alert: 'detection',
  anomaly: 'detection',
  dns: 'dns',
  tls: 'tls',
  http: 'http',
  ssh: 'network',
  flow: 'network',
  netflow: 'network',
  fileinfo: 'file',
  smb: 'network',
  ftp: 'network',
  smtp: 'network',
  krb5: 'authentication',
};
/** Event types that carry no security semantics for the platform and are refused up front. */
const UNSUPPORTED = new Set(['stats', 'engine', 'packet']);

const SEVERITY: Record<number, Severity> = { 1: 'high', 2: 'medium', 3: 'low', 4: 'info' };
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, max = 256) => (typeof v === 'string' ? v.slice(0, max) : undefined);
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/** Suricata timestamps look like `2026-10-18T12:00:00.123456+0000`; JS Date needs `+00:00` and ms. */
export function parseEveTimestamp(ts: unknown): string | null {
  if (typeof ts !== 'string') return null;
  const fixed = ts.replace(/(\.\d{3})\d+/, '$1').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  const d = new Date(fixed);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Projects an EVE record onto the bounded, allow-listed `engine` bag. Payload, packet and
 * printable-payload fields are never copied — raw bytes are a retention/evidence decision,
 * not part of the normalized event.
 */
function engineFields(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const copy = (key: string, v: unknown) => {
    if (v !== undefined) out[key] = v;
  };
  copy('app_proto', str(r.app_proto, 32));
  copy('flow_id', num(r.flow_id) ?? str(r.flow_id, 32));
  copy('in_iface', str(r.in_iface, 64));
  copy('community_id', str(r.community_id, 128));
  copy('pcap_cnt', num(r.pcap_cnt));
  if (isObj(r.alert)) {
    const a = r.alert;
    const metadata = isObj(a.metadata)
      ? Object.fromEntries(
          Object.entries(a.metadata)
            .slice(0, 16)
            .map(([k, v]) => [
              k,
              Array.isArray(v) ? v.slice(0, 8).map((x) => str(x, 128)) : str(v, 128),
            ]),
        )
      : undefined;
    out.alert = {
      signature: str(a.signature, 512),
      category: str(a.category, 128),
      action: str(a.action, 16),
      gid: num(a.gid),
      signature_id: num(a.signature_id),
      rev: num(a.rev),
      severity: num(a.severity),
      metadata,
    };
  }
  if (isObj(r.dns))
    out.dns = {
      type: str(r.dns.type, 16),
      rrname: str(r.dns.rrname, 512),
      rrtype: str(r.dns.rrtype, 16),
      rcode: str(r.dns.rcode, 16),
      tx_id: num(r.dns.tx_id),
    };
  if (isObj(r.tls))
    out.tls = {
      sni: str(r.tls.sni, 256),
      subject: str(r.tls.subject, 256),
      issuerdn: str(r.tls.issuerdn, 256),
      version: str(r.tls.version, 16),
      fingerprint: str(r.tls.fingerprint, 128),
      ja3: isObj(r.tls.ja3) ? { hash: str(r.tls.ja3.hash, 64) } : undefined,
      ja3s: isObj(r.tls.ja3s) ? { hash: str(r.tls.ja3s.hash, 64) } : undefined,
    };
  if (isObj(r.http))
    out.http = {
      hostname: str(r.http.hostname, 256),
      url: str(r.http.url, 1024),
      http_method: str(r.http.http_method, 16),
      status: num(r.http.status),
      http_user_agent: str(r.http.http_user_agent, 256),
      length: num(r.http.length),
    };
  if (isObj(r.flow))
    out.flow = {
      pkts_toserver: num(r.flow.pkts_toserver),
      pkts_toclient: num(r.flow.pkts_toclient),
      bytes_toserver: num(r.flow.bytes_toserver),
      bytes_toclient: num(r.flow.bytes_toclient),
      state: str(r.flow.state, 16),
      reason: str(r.flow.reason, 16),
      start: str(r.flow.start, 40),
      end: str(r.flow.end, 40),
    };
  if (isObj(r.ssh))
    out.ssh = {
      client: isObj(r.ssh.client)
        ? { software_version: str(r.ssh.client.software_version, 128) }
        : undefined,
      server: isObj(r.ssh.server)
        ? { software_version: str(r.ssh.server.software_version, 128) }
        : undefined,
    };
  if (isObj(r.fileinfo))
    out.fileinfo = {
      filename: str(r.fileinfo.filename, 512),
      size: num(r.fileinfo.size),
      sha256: str(r.fileinfo.sha256, 64),
      magic: str(r.fileinfo.magic, 128),
    };
  if (isObj(r.anomaly))
    out.anomaly = {
      type: str(r.anomaly.type, 32),
      event: str(r.anomaly.event, 128),
      layer: str(r.anomaly.layer, 32),
    };
  return JSON.parse(JSON.stringify(out)) as Record<string, unknown>; // drop undefined keys
}

/** Maps one Suricata EVE JSON record to the normalized event envelope (v1). Pure; no I/O. */
export function normalizeEveRecord(
  raw: unknown,
  ctx: { sensorId: string | null; eventId: string; ingestTime: string },
): EveNormalizeResult {
  if (!isObj(raw)) return { ok: false, reason: 'not_an_object' };
  const eventType = str(raw.event_type, 32);
  if (!eventType) return { ok: false, reason: 'missing_event_type' };
  if (UNSUPPORTED.has(eventType))
    return { ok: false, reason: `unsupported_event_type:${eventType}` };
  const eventTime = parseEveTimestamp(raw.timestamp);
  if (!eventTime) return { ok: false, reason: 'invalid_timestamp' };

  const alert = isObj(raw.alert) ? raw.alert : null;
  const severity: Severity = alert ? (SEVERITY[num(alert.severity) ?? 0] ?? 'info') : 'info';
  const gid = alert ? num(alert.gid) : undefined;
  const sid = alert ? num(alert.signature_id) : undefined;
  const rev = alert ? num(alert.rev) : undefined;
  const ruleId = alert && sid !== undefined ? `${gid ?? 1}:${sid}:${rev ?? 0}` : null;
  const metadata = alert && isObj(alert.metadata) ? alert.metadata : null;
  const techniques =
    metadata && Array.isArray(metadata.mitre_technique_id)
      ? metadata.mitre_technique_id
          .filter((t): t is string => typeof t === 'string' && TECHNIQUE.test(t))
          .slice(0, 16)
      : [];
  const flowId = num(raw.flow_id) ?? str(raw.flow_id, 32);
  const correlationIds = [
    ...(flowId !== undefined ? [`flow:${flowId}`] : []),
    ...(str(raw.community_id, 128) ? [`community:${str(raw.community_id, 128)}`] : []),
  ];

  const candidate = {
    schemaVersion: '1.0' as const,
    eventId: ctx.eventId,
    eventTime,
    ingestTime: ctx.ingestTime,
    sourceProduct: 'suricata' as const,
    sourceSensorId: ctx.sensorId,
    category: CATEGORY[eventType] ?? ('other' as const),
    type: eventType,
    severity,
    confidence: alert ? ('medium' as const) : ('high' as const),
    srcAssetId: null,
    dstAssetId: null,
    srcIp: str(raw.src_ip, 64) ?? null,
    dstIp: str(raw.dest_ip, 64) ?? null,
    srcPort: num(raw.src_port) ?? null,
    dstPort: num(raw.dest_port) ?? null,
    protocol: str(raw.proto, 32)?.toLowerCase() ?? null,
    ruleId,
    threatClassification: techniques,
    incidentId: null,
    evidenceRefs: [],
    correlationIds,
    originalRef: null,
    engine: engineFields(raw),
  };
  const parsed = NormalizedEvent.safeParse(candidate);
  if (!parsed.success)
    return {
      ok: false,
      reason: `schema:${parsed.error.issues[0]?.path.join('.') ?? '?'}:${parsed.error.issues[0]?.message ?? 'invalid'}`,
    };
  return { ok: true, event: parsed.data };
}

/** Title shown in the alert queue for a detection event. */
export function alertTitleFor(event: NormalizedEvent): string {
  const alert = event.engine.alert as { signature?: string } | undefined;
  const notice = event.engine.notice as { msg?: string; note?: string } | undefined;
  return (
    alert?.signature ??
    notice?.msg ??
    notice?.note ??
    `${event.sourceProduct} ${event.type}`
  ).slice(0, 256);
}
