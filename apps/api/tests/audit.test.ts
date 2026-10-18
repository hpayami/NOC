import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { AuditService, GENESIS_HASH, canonicalJson } from '../src/audit/service';
import {
  authed,
  createHarness,
  loginAdmin,
  resetDatabase,
  seedAdmin,
  type Harness,
  jsonOf,
} from './helpers';

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  h.limiter.reset();
  await seedAdmin(h);
});

describe('tamper-evident audit trail', () => {
  it('canonical JSON is key-order independent', () => {
    expect(canonicalJson({ b: 1, a: { d: [1, 2], c: null } })).toBe(
      canonicalJson({ a: { c: null, d: [1, 2] }, b: 1 }),
    );
  });

  it('chains from genesis and verifies clean', async () => {
    const { token } = await loginAdmin(h);
    const r = await h.app.request('/api/v1/audit/verify', {
      method: 'POST',
      headers: authed(token),
    });
    expect(r.status).toBe(200);
    const body = await jsonOf(r);
    expect(body.valid).toBe(true);
    expect(body.eventsChecked).toBeGreaterThanOrEqual(2); // bootstrap + login
    const [first] = (await h.handle.db.execute(
      sql`select prev_hash from audit_events order by seq asc limit 1`,
    )) as unknown as Array<{ prev_hash: string }>;
    expect(first!.prev_hash).toBe(GENESIS_HASH);
  });

  it('detects an altered row', async () => {
    const { token } = await loginAdmin(h);
    await h.handle.db.execute(
      sql`update audit_events set action = 'auth.login_forged' where seq = 2`,
    );
    const r = await h.app.request('/api/v1/audit/verify', {
      method: 'POST',
      headers: authed(token),
    });
    const body = await jsonOf(r);
    expect(body.valid).toBe(false);
    expect(body.firstBrokenSeq).toBe(2);
    expect(body.reason).toMatch(/altered/);
  });

  it('detects a deleted row (chain gap)', async () => {
    const { token } = await loginAdmin(h);
    await h.handle.db.execute(sql`delete from audit_events where seq = 1`);
    const body = await jsonOf(
      await h.app.request('/api/v1/audit/verify', { method: 'POST', headers: authed(token) }),
    );
    expect(body.valid).toBe(false);
    expect(body.reason).toMatch(/prev_hash/);
  });

  it('stays linear under concurrent writers', async () => {
    const audit = new AuditService(h.handle.db);
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        audit.record({
          actorId: null,
          actorLabel: 'test',
          action: 'test.concurrent',
          outcome: 'success',
          metadata: { i },
        }),
      ),
    );
    const result = await audit.verify();
    expect(result.valid).toBe(true);
    expect(result.eventsChecked).toBeGreaterThanOrEqual(25);
  });

  it('lists audit events newest first with cursor pagination', async () => {
    const { token } = await loginAdmin(h);
    const r1 = await h.app.request('/api/v1/audit?limit=1', { headers: authed(token) });
    const p1 = await jsonOf(r1);
    expect(p1.items).toHaveLength(1);
    expect(p1.nextCursor).toBeTruthy();
    const r2 = await h.app.request(`/api/v1/audit?limit=5&cursor=${p1.nextCursor}`, {
      headers: authed(token),
    });
    const p2 = await jsonOf(r2);
    expect(p2.items[0].seq).toBeLessThan(p1.items[0].seq);
  });
});
