import type { Severity } from '../enums';

export interface ParsedRule {
  enabled: boolean;
  action: string;
  protocol: string;
  src: string;
  srcPort: string;
  direction: string;
  dst: string;
  dstPort: string;
  msg: string;
  gid: number;
  sid: number;
  rev: number;
  classtype: string | null;
  metadata: Record<string, string[]>;
  references: string[];
  raw: string;
  line: number;
}

export interface RuleParseResult {
  rules: ParsedRule[];
  errors: Array<{ line: number; message: string }>;
}

const HEADER =
  /^(#\s*)?(alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/;

/** Splits the option body on `;` while respecting quoted strings and `\;` escapes. */
function splitOptions(body: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (ch === '\\' && i + 1 < body.length) {
      cur += ch + body[i + 1];
      i++;
      continue;
    }
    if (ch === '"') inQuote = !inQuote;
    if (ch === ';' && !inQuote) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Parses Suricata/Snort-style rule text. Disabled (`#`-prefixed) rules are kept with `enabled: false`. */
export function parseSuricataRules(text: string): RuleParseResult {
  const rules: ParsedRule[] = [];
  const errors: RuleParseResult['errors'] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.trim();
    if (!raw) continue;
    if (raw.startsWith('#') && !HEADER.test(raw)) continue; // ordinary comment
    const m = HEADER.exec(raw);
    if (!m) {
      errors.push({ line: i + 1, message: 'unparseable rule header' });
      continue;
    }
    const [, disabled, action, protocol, src, srcPort, direction, dst, dstPort, body] = m;
    const metadata: Record<string, string[]> = {};
    const references: string[] = [];
    let msg = '';
    let sid: number | undefined;
    let gid = 1;
    let rev = 0;
    let classtype: string | null = null;
    for (const opt of splitOptions(body!)) {
      const colon = opt.indexOf(':');
      const key = (colon >= 0 ? opt.slice(0, colon) : opt).trim();
      const value = colon >= 0 ? opt.slice(colon + 1).trim() : '';
      switch (key) {
        case 'msg':
          msg = value.replace(/^"|"$/g, '').slice(0, 512);
          break;
        case 'sid':
          sid = Number(value);
          break;
        case 'gid':
          gid = Number(value) || 1;
          break;
        case 'rev':
          rev = Number(value) || 0;
          break;
        case 'classtype':
          classtype = value.slice(0, 64);
          break;
        case 'reference':
          if (references.length < 16) references.push(value.slice(0, 256));
          break;
        case 'metadata':
          for (const pair of value.split(',')) {
            const [k, ...rest] = pair.trim().split(/\s+/);
            if (!k || rest.length === 0) continue;
            (metadata[k] ??= []).push(rest.join(' ').slice(0, 128));
          }
          break;
        default:
          break;
      }
    }
    if (!sid || !Number.isInteger(sid) || sid <= 0) {
      errors.push({ line: i + 1, message: 'missing or invalid sid' });
      continue;
    }
    if (!msg) {
      errors.push({ line: i + 1, message: `sid ${sid}: missing msg` });
      continue;
    }
    rules.push({
      enabled: !disabled,
      action: action!,
      protocol: protocol!,
      src: src!,
      srcPort: srcPort!,
      direction: direction!,
      dst: dst!,
      dstPort: dstPort!,
      msg,
      gid,
      sid,
      rev,
      classtype,
      metadata,
      references,
      raw,
      line: i + 1,
    });
  }
  return { rules, errors };
}

const CLASSTYPE_SEVERITY: Record<string, Severity> = {
  'attempted-admin': 'high',
  'attempted-user': 'high',
  'successful-admin': 'critical',
  'successful-user': 'critical',
  'trojan-activity': 'high',
  'command-and-control': 'high',
  'targeted-activity': 'high',
  'exploit-kit': 'high',
  'domain-c2': 'high',
  'credential-theft': 'high',
  'attempted-recon': 'medium',
  'policy-violation': 'medium',
  'misc-attack': 'medium',
  'web-application-attack': 'medium',
  'bad-unknown': 'medium',
  'attempted-dos': 'medium',
  'denial-of-service': 'medium',
  'misc-activity': 'low',
  'not-suspicious': 'info',
  'protocol-command-decode': 'info',
  unknown: 'low',
};

/** Rule severity: author-declared signature_severity first, then classtype, then medium. */
export function ruleSeverity(rule: Pick<ParsedRule, 'classtype' | 'metadata'>): Severity {
  const declared = rule.metadata['signature_severity']?.[0]?.toLowerCase();
  if (declared === 'critical') return 'critical';
  if (declared === 'major') return 'high';
  if (declared === 'minor') return 'medium';
  if (declared === 'informational') return 'info';
  return (rule.classtype && CLASSTYPE_SEVERITY[rule.classtype]) || 'medium';
}

export function ruleTechniques(rule: Pick<ParsedRule, 'metadata'>): string[] {
  return (rule.metadata['mitre_technique_id'] ?? [])
    .filter((t) => /^T\d{4}(\.\d{3})?$/.test(t))
    .slice(0, 16);
}
