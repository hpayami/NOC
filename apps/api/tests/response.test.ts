import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { ResponseActionRecord } from '@noc/shared';
import {
  authed,
  createHarness,
  createUser,
  jsonOf,
  login,
  loginAdmin,
  resetDatabase,
  seedAdmin,
  type Harness,
} from './helpers';

let h: Harness;
let admin: { token: string };
let analyst: string; // soc_analyst: response.propose, incidents.manage
let responder: string; // incident_responder: response.propose/execute/rollback
let sec1: string; // security_admin: response.approve
let sec2: string; // second independent approver
let auditor: string; // response.read only
let incidentId: string;
const PW = 'response-password-that-is-long-enough';

const post = (path: string, token: string, body: unknown = {}) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });

const proposal = (over: Record<string, unknown> = {}) => ({
  kind: 'block_indicator',
  incidentId,
  targetType: 'ip',
  targetRef: '203.0.113.10',
  justification: 'C2 beaconing observed from three hosts to this address',
  rollbackPlan: 'Remove the block entry from the perimeter firewall and verify egress',
  ...over,
});

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(sql`truncate table security_events, incident_events cascade`);
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['analyst@test.local', 'soc_analyst'],
    ['responder@test.local', 'incident_responder'],
    ['sec1@test.local', 'security_admin'],
    ['sec2@test.local', 'security_admin'],
    ['auditor@test.local', 'read_only_auditor'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  const tokens = await Promise.all(
    ['analyst', 'responder', 'sec1', 'sec2', 'auditor'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  );
  [analyst, responder, sec1, sec2, auditor] = tokens as [string, string, string, string, string];
  incidentId = (
    await jsonOf(
      await post('/api/v1/incidents', analyst, { title: 'Beaconing', severity: 'medium' }),
    )
  ).id;
});

describe('response actions', () => {
  it('lists executors honestly and validates proposals', async () => {
    const cat = await jsonOf(
      await h.app.request('/api/v1/response-actions/executors', { headers: authed(auditor) }),
    );
    const byKind = Object.fromEntries(cat.items.map((e: { kind: string }) => [e.kind, e]));
    expect(byKind.collect_evidence).toMatchObject({ available: true, requiredApprovals: 0 });
    expect(byKind.isolate_endpoint).toMatchObject({ available: false, requiredApprovals: 2 });
    expect(byKind.enable_inline_prevention).toMatchObject({
      available: false,
      requiredApprovals: 2,
    });
    expect((await post('/api/v1/response-actions', auditor, proposal())).status).toBe(403);
    expect(
      (await post('/api/v1/response-actions', analyst, proposal({ rollbackPlan: 'none' }))).status,
    ).toBe(400);
    expect(
      (await post('/api/v1/response-actions', analyst, proposal({ targetRef: 'not-an-ip' })))
        .status,
    ).toBe(400);
    expect(
      (
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ targetType: 'asset', targetRef: '00000000-0000-4000-8000-000000000000' }),
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'escalate', incidentId: null }),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'enable_inline_prevention' }),
        )
      ).status,
    ).toBe(403); // needs ips.propose
  });

  it('runs propose → two-person approval → execute refusal for unavailable executors, with SoD', async () => {
    const created = await post('/api/v1/response-actions', analyst, proposal());
    expect(created.status).toBe(201);
    const a = ResponseActionRecord.parse(await jsonOf(created));
    expect(a).toMatchObject({
      status: 'pending_approval',
      requiredApprovals: 1,
      approvalsGranted: 0,
      executorAvailable: false,
      executedAt: null,
    });
    expect(new Date(a.expiresAt!).getTime()).toBeGreaterThan(Date.now());

    // Analysts cannot approve (no permission); the proposer could not even if they held it.
    expect(
      (
        await post(`/api/v1/response-actions/${a.id}/approve`, analyst, {
          justification: 'looks fine',
        })
      ).status,
    ).toBe(403);
    expect((await post(`/api/v1/response-actions/${a.id}/execute`, responder, {})).status).toBe(
      409,
    ); // not approved yet
    const approved = ResponseActionRecord.parse(
      await jsonOf(
        await post(`/api/v1/response-actions/${a.id}/approve`, sec1, {
          justification: 'Indicator confirmed malicious via two sources',
        }),
      ),
    );
    expect(approved).toMatchObject({ status: 'approved', approvalsGranted: 1 });
    expect(
      (await post(`/api/v1/response-actions/${a.id}/approve`, sec1, { justification: 'again' }))
        .status,
    ).toBe(409); // already decided

    // No firewall integration exists: execution is refused and the action stays approved.
    const exec = await post(`/api/v1/response-actions/${a.id}/execute`, responder, {});
    expect(exec.status).toBe(409);
    expect((await jsonOf(exec)).error.message).toMatch(/integration; none is configured/);
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/response-actions/${a.id}`, { headers: authed(auditor) }),
        )
      ).status,
    ).toBe('approved');

    // Two-person rule for isolation: one approval is not enough, the same approver cannot double up.
    const iso = ResponseActionRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/response-actions',
          responder,
          proposal({ kind: 'isolate_endpoint', targetType: 'ip', targetRef: '10.0.0.7' }),
        ),
      ),
    );
    expect(iso.requiredApprovals).toBe(2);
    expect(
      (
        await jsonOf(
          await post(`/api/v1/response-actions/${iso.id}/approve`, sec1, {
            justification: 'Host is beaconing',
          }),
        )
      ).status,
    ).toBe('pending_approval');
    expect(
      (await post(`/api/v1/response-actions/${iso.id}/approve`, sec1, { justification: 'second' }))
        .status,
    ).toBe(409);
    expect(
      (
        await jsonOf(
          await post(`/api/v1/response-actions/${iso.id}/approve`, sec2, {
            justification: 'Concur; business owner informed',
          }),
        )
      ).status,
    ).toBe('approved');
    // Rejection ends the workflow.
    const rej = ResponseActionRecord.parse(
      await jsonOf(
        await post('/api/v1/response-actions', analyst, proposal({ targetRef: '203.0.113.11' })),
      ),
    );
    expect(
      (
        await jsonOf(
          await post(`/api/v1/response-actions/${rej.id}/reject`, sec1, {
            justification: 'Shared CDN address; collateral impact',
          }),
        )
      ).status,
    ).toBe('rejected');
    expect(
      (
        await post(`/api/v1/response-actions/${rej.id}/approve`, sec2, {
          justification: 'late approval',
        })
      ).status,
    ).toBe(409);

    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin.token) }),
    );
    const acts = audit.items.map(
      (e: { action: string; outcome: string }) => `${e.action}:${e.outcome}`,
    );
    expect(acts).toEqual(
      expect.arrayContaining([
        'response.propose:success',
        'response.approve:success',
        'response.approve:failure',
        'response.execute:failure',
        'response.reject:success',
      ]),
    );
  });

  it('executes in-platform actions, verifies them, enforces approver≠executor and rolls back', async () => {
    // Seed two events for the target so evidence collection has something real to reference.
    for (const i of [1, 2])
      await h.handle.db
        .execute(sql`insert into security_events (id, schema_version, event_time, source_product, category, type, severity, src_ip, dst_ip, dedup_hash)
        values (gen_random_uuid(), '1.0', now() - interval '1 hour', 'suricata', 'network', 'flow', 'info', '10.0.0.7'::inet, '203.0.113.10'::inet, ${`ev-${i}`})`);
    const ev = ResponseActionRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'collect_evidence', targetRef: '10.0.0.7' }),
        ),
      ),
    );
    expect(ev.status).toBe('approved'); // advisory kinds need no approval
    expect((await post(`/api/v1/response-actions/${ev.id}/execute`, analyst, {})).status).toBe(403); // no response.execute
    const done = ResponseActionRecord.parse(
      await jsonOf(
        await post(`/api/v1/response-actions/${ev.id}/execute`, responder, {
          note: 'Collected before containment',
        }),
      ),
    );
    expect(done).toMatchObject({
      status: 'executed',
      verificationResult: 'passed',
      executedBy: expect.any(String),
    });
    expect(done.result.count).toBe(2);
    expect(
      (done.result.evidence as Array<{ sha256: string }>).every((e) =>
        /^[0-9a-f]{64}$/.test(e.sha256),
      ),
    ).toBe(true);

    // Escalation raises the incident and is reversible.
    const esc = ResponseActionRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'escalate', targetType: 'incident', targetRef: incidentId }),
        ),
      ),
    );
    const execd = ResponseActionRecord.parse(
      await jsonOf(await post(`/api/v1/response-actions/${esc.id}/execute`, responder, {})),
    );
    expect(execd.result).toMatchObject({ previousSeverity: 'medium', severity: 'high' });
    let inc = await jsonOf(
      await h.app.request(`/api/v1/incidents/${incidentId}`, { headers: authed(analyst) }),
    );
    expect(inc.incident.severity).toBe('high');
    expect(
      inc.timeline.filter((e: { kind: string }) => e.kind === 'response_action').length,
    ).toBeGreaterThanOrEqual(4);
    expect((await post(`/api/v1/response-actions/${esc.id}/rollback`, analyst, {})).status).toBe(
      403,
    );
    const rb = ResponseActionRecord.parse(
      await jsonOf(
        await post(`/api/v1/response-actions/${esc.id}/rollback`, responder, {
          note: 'False alarm',
        }),
      ),
    );
    expect(rb).toMatchObject({ status: 'rolled_back' });
    expect(rb.rolledBackAt).toBeTruthy();
    inc = await jsonOf(
      await h.app.request(`/api/v1/incidents/${incidentId}`, { headers: authed(analyst) }),
    );
    expect(inc.incident.severity).toBe('medium');
    expect((await post(`/api/v1/response-actions/${esc.id}/rollback`, responder, {})).status).toBe(
      409,
    );

    // Separation of duties at user level: give the responder approval rights is impossible by role
    // (approve/execute are a separated pair); simulate an approver executing via a direct approval row.
    const sodAction = ResponseActionRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'recommend_isolation', targetRef: '10.0.0.7' }),
        ),
      ),
    );
    const responderId = (
      await jsonOf(await h.app.request('/api/v1/auth/me', { headers: authed(responder) }))
    ).id;
    await h.handle.db.execute(
      sql`insert into approvals (subject_type, subject_id, approver_id, decision, justification) values ('response_action', ${sodAction.id}, ${responderId}, 'approved', 'seeded')`,
    );
    expect(
      (await post(`/api/v1/response-actions/${sodAction.id}/execute`, responder, {})).status,
    ).toBe(403);

    // Expiry: an approved action past its expiry cannot be executed and is marked expired.
    const old = ResponseActionRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/response-actions',
          analyst,
          proposal({ kind: 'collect_evidence', targetRef: '10.0.0.8', expiresInHours: 1 }),
        ),
      ),
    );
    await h.handle.db.execute(
      sql`update response_actions set expires_at = now() - interval '1 minute' where id = ${old.id}`,
    );
    expect((await post(`/api/v1/response-actions/${old.id}/execute`, responder, {})).status).toBe(
      409,
    );
    expect(
      (
        await jsonOf(
          await h.app.request(`/api/v1/response-actions/${old.id}`, { headers: authed(auditor) }),
        )
      ).status,
    ).toBe('expired');

    const listRes = await h.app.request(
      `/api/v1/response-actions?incidentId=${incidentId}&status=executed`,
      { headers: authed(auditor) },
    );
    const list = await jsonOf(listRes);
    expect(list, JSON.stringify(list)).toHaveProperty('items');
    expect(list.items.map((r: { id: string }) => r.id)).toEqual([ev.id]);
  });
});
