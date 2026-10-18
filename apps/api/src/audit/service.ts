import { createHash } from 'node:crypto';
import { asc, gt, sql } from 'drizzle-orm';
import type { AuditVerifyResponse } from '@noc/shared';
import type { Db, DbTx } from '../db/client';
import { auditEvents } from '../db/schema';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditInput {
  actorId: string | null;
  actorLabel: string;
  action: string;
  outcome: 'success' | 'denied' | 'failure';
  targetType?: string | null;
  targetId?: string | null;
  requestId?: string | null;
  sourceIp?: string | null;
  metadata?: Record<string, unknown>;
}

/** Deterministic JSON: sorted keys, no whitespace, so hashes are reproducible across runtimes. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export interface HashableAuditRow {
  seq: number;
  occurredAt: Date;
  actorId: string | null;
  actorLabel: string;
  action: string;
  outcome: 'success' | 'denied' | 'failure';
  targetType: string | null;
  targetId: string | null;
  requestId: string | null;
  sourceIp: string | null;
  metadata: Record<string, unknown>;
  prevHash: string;
}

export function computeAuditHash(row: HashableAuditRow): string {
  const material = [
    String(row.seq),
    row.occurredAt.toISOString(),
    row.actorId ?? '',
    row.actorLabel,
    row.action,
    row.outcome,
    row.targetType ?? '',
    row.targetId ?? '',
    row.requestId ?? '',
    row.sourceIp ?? '',
    canonicalJson(row.metadata),
    row.prevHash,
  ].join('|');
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

export class AuditService {
  constructor(private readonly db: Db) {}

  /**
   * Appends one audit event inside `tx` (or its own transaction). A transaction-scoped advisory lock
   * serializes writers so the hash chain is linear even under concurrent requests.
   */
  async record(input: AuditInput, tx?: DbTx): Promise<{ seq: number; hash: string }> {
    const run = async (t: DbTx) => {
      await t.execute(sql`select pg_advisory_xact_lock(hashtext('noc_audit_chain'))`);
      const [last] = await t
        .select({ seq: auditEvents.seq, hash: auditEvents.hash })
        .from(auditEvents)
        .orderBy(sql`${auditEvents.seq} desc`)
        .limit(1);
      const [{ nextSeq }] = (await t.execute(
        sql`select nextval(pg_get_serial_sequence('audit_events','seq'))::bigint as "nextSeq"`,
      )) as unknown as [{ nextSeq: string | number }];
      const seq = Number(nextSeq);
      const prevHash = last?.hash ?? GENESIS_HASH;
      const occurredAt = new Date();
      const metadata = input.metadata ?? {};
      const row: HashableAuditRow = {
        seq,
        occurredAt,
        actorId: input.actorId,
        actorLabel: input.actorLabel,
        action: input.action,
        outcome: input.outcome,
        targetType: input.targetType ?? null,
        targetId: input.targetId ?? null,
        requestId: input.requestId ?? null,
        sourceIp: input.sourceIp ?? null,
        metadata,
        prevHash,
      };
      const hash = computeAuditHash(row);
      await t.insert(auditEvents).values({ ...row, hash });
      return { seq, hash };
    };
    return tx ? run(tx) : this.db.transaction(run);
  }

  /** Walks the chain in sequence order and recomputes every hash. */
  async verify(): Promise<AuditVerifyResponse> {
    let prevHash = GENESIS_HASH;
    let lastSeq = 0;
    let checked = 0;
    const batch = 500;
    for (;;) {
      const rows = await this.db
        .select()
        .from(auditEvents)
        .where(gt(auditEvents.seq, lastSeq))
        .orderBy(asc(auditEvents.seq))
        .limit(batch);
      if (rows.length === 0) break;
      for (const r of rows) {
        if (r.prevHash !== prevHash) {
          return {
            valid: false,
            eventsChecked: checked,
            firstBrokenSeq: r.seq,
            reason: 'prev_hash mismatch (gap or reorder)',
          };
        }
        const expected = computeAuditHash({ ...r, metadata: r.metadata ?? {} });
        if (expected !== r.hash) {
          return {
            valid: false,
            eventsChecked: checked,
            firstBrokenSeq: r.seq,
            reason: 'content hash mismatch (row altered)',
          };
        }
        prevHash = r.hash;
        lastSeq = r.seq;
        checked++;
      }
      if (rows.length < batch) break;
    }
    return { valid: true, eventsChecked: checked, firstBrokenSeq: null, reason: null };
  }
}
