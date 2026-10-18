import net from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import {
  AssessmentRun,
  EngagementRecord,
  EngagementReport,
  FindingRecord,
  RunDetail,
} from '@noc/shared';
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
let red: string; // red_team_operator: assessments.plan/execute, findings.manage
let sec: string; // security_admin: assessments.approve
let vuln: string; // vulnerability_analyst: findings.manage
let auditor: string; // read only
let blue: string; // blue_team_engineer: assessments.read without findings.read
const PW = 'assessment-password-that-is-long-enough';

const hourAgo = () => new Date(Date.now() - 3_600_000).toISOString();
const hourAhead = () => new Date(Date.now() + 3_600_000).toISOString();
const post = (path: string, token: string, body: unknown = {}) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });
const get = (path: string, token: string) => h.app.request(path, { headers: authed(token) });

const scope = (over: Record<string, unknown> = {}) => ({
  includeCidrs: [],
  includeAddresses: ['127.0.0.1'],
  excludeCidrs: [],
  excludeAddresses: [],
  allowPublicAddresses: false,
  allowedTechniques: ['host_discovery', 'service_fingerprint', 'vulnerability_scan'],
  windowStart: hourAgo(),
  windowEnd: hourAhead(),
  maxConcurrency: 2,
  maxRequestsPerSecond: 50,
  ...over,
});
const engagement = (over: Record<string, unknown> = {}) => ({
  reference: 'ENG-2026-007',
  authorizingOrganization: 'Example Holding',
  authorizationReference: 'Contract C-4411 / change CHG-9001',
  objective: 'Validate exposure of lab services from the user VLAN position',
  scope: scope(),
  stopConditions: ['Any production impact reported by NOC'],
  emergencyContact: 'soc-duty@example.test',
  ...over,
});

/** Listens on a risky-service port so the fingerprint worker has something real to find. */
function listenRisky(): Promise<{ server: net.Server; port: number }> {
  const candidates = [11211, 27017, 9200, 6379];
  return new Promise((resolve, reject) => {
    const tryNext = (i: number) => {
      if (i >= candidates.length) return reject(new Error('no risky port free'));
      const server = net.createServer((s) => s.end());
      server.once('error', () => tryNext(i + 1));
      server.listen(candidates[i], '127.0.0.1', () => resolve({ server, port: candidates[i]! }));
    };
    tryNext(0);
  });
}

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table asset_observations, asset_interfaces, network_segments, assessment_runs cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['red@test.local', 'red_team_operator'],
    ['sec@test.local', 'security_admin'],
    ['vuln@test.local', 'vulnerability_analyst'],
    ['auditor@test.local', 'read_only_auditor'],
    ['blue@test.local', 'blue_team_engineer'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  const t = await Promise.all(
    ['red', 'sec', 'vuln', 'auditor', 'blue'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  );
  [red, sec, vuln, auditor, blue] = t as [string, string, string, string, string];
  expect(
    (
      await post('/api/v1/network/segments', admin.token, {
        name: 'lab-loopback',
        site: 'lab',
        cidr: '127.0.0.0/8',
        vlanId: null,
        activeDiscoveryAllowed: true,
        description: null,
      })
    ).status,
  ).toBe(201);
});

describe('assessment engagements', () => {
  it('requires authorisation, independent approval and an open window before anything runs', async () => {
    expect((await post('/api/v1/assessments/engagements', sec, engagement())).status).toBe(403); // approvers cannot plan
    expect(
      (
        await post(
          '/api/v1/assessments/engagements',
          red,
          engagement({ authorizationReference: '' }),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await post(
          '/api/v1/assessments/engagements',
          red,
          engagement({ scope: scope({ windowEnd: hourAgo() }) }),
        )
      ).status,
    ).toBe(400);
    const e = EngagementRecord.parse(
      await jsonOf(await post('/api/v1/assessments/engagements', red, engagement())),
    );
    expect(e).toMatchObject({
      status: 'draft',
      scopeVersion: 1,
      approvedScopeVersion: null,
      runCount: 0,
    });
    const go = (to: string, token: string, reason?: string) =>
      post(`/api/v1/assessments/engagements/${e.id}/transition`, token, {
        to,
        ...(reason ? { reason } : {}),
      });

    expect((await go('active', red)).status).toBe(409); // draft cannot activate
    expect(
      (
        await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
          technique: 'host_discovery',
        })
      ).status,
    ).toBe(409);
    expect((await jsonOf(await go('pending_approval', red))).status).toBe('pending_approval');
    expect(
      (
        await post(`/api/v1/assessments/engagements/${e.id}/approve`, red, {
          justification: 'self approval attempt',
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await jsonOf(
          await post(`/api/v1/assessments/engagements/${e.id}/reject`, sec, {
            justification: 'Stop conditions too vague; add NOC contact',
          }),
        )
      ).status,
    ).toBe('draft');
    await go('pending_approval', red);
    const approved = EngagementRecord.parse(
      await jsonOf(
        await post(`/api/v1/assessments/engagements/${e.id}/approve`, sec, {
          justification: 'Authorisation C-4411 verified with legal',
        }),
      ),
    );
    expect(approved).toMatchObject({ status: 'approved', approvedScopeVersion: 1 });
    expect(approved.approvals).toHaveLength(2);
    expect((await go('active', sec)).status).toBe(403); // approvers do not execute
    expect((await jsonOf(await go('active', red))).status).toBe('active');

    // A scope change invalidates the approval: back to pending, runs refused until re-approved.
    const changed = EngagementRecord.parse(
      await jsonOf(
        await h.app.request(`/api/v1/assessments/engagements/${e.id}/scope`, {
          method: 'PUT',
          headers: authed(red),
          body: JSON.stringify({
            scope: scope({ includeAddresses: ['127.0.0.1', '127.0.0.2'] }),
            reason: 'Add second lab host',
          }),
        }),
      ),
    );
    expect(changed).toMatchObject({
      status: 'pending_approval',
      scopeVersion: 2,
      approvedScopeVersion: 1,
    });
    expect(
      (
        await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
          technique: 'host_discovery',
        })
      ).status,
    ).toBe(409);
    await post(`/api/v1/assessments/engagements/${e.id}/approve`, sec, {
      justification: 'Second host is in the same lab segment',
    });
    expect((await jsonOf(await go('active', red))).status).toBe('active');
    expect(
      (await jsonOf(await get(`/api/v1/assessments/engagements/${e.id}`, auditor)))
        .approvedScopeVersion,
    ).toBe(2);

    // Completion needs a reason; closed engagements are final.
    expect((await go('completed', red)).status).toBe(409);
    expect(
      (await jsonOf(await go('completed', red, 'Objectives covered; report delivered'))).status,
    ).toBe('completed');
    expect((await go('active', red)).status).toBe(409);
    const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
    const acts = audit.items.map(
      (x: { action: string; outcome: string }) => `${x.action}:${x.outcome}`,
    );
    expect(acts).toEqual(
      expect.arrayContaining([
        'assessments.create:success',
        'assessments.reject:success',
        'assessments.approve:success',
        'assessments.transition:denied',
        'assessments.scope_change:success',
      ]),
    );
  });

  it('runs only authorised, executable techniques inside the worker policy and records findings honestly', async () => {
    const cat = await jsonOf(await get('/api/v1/assessments/techniques', auditor));
    expect(
      cat.items.find((t: { technique: string }) => t.technique === 'service_fingerprint')
        .executable,
    ).toBe(true);
    expect(
      cat.items.find((t: { technique: string }) => t.technique === 'vulnerability_scan').executable,
    ).toBe(false);

    const e = EngagementRecord.parse(
      await jsonOf(await post('/api/v1/assessments/engagements', red, engagement())),
    );
    await post(`/api/v1/assessments/engagements/${e.id}/transition`, red, {
      to: 'pending_approval',
    });
    await post(`/api/v1/assessments/engagements/${e.id}/approve`, sec, {
      justification: 'Authorisation verified; lab only',
    });
    await post(`/api/v1/assessments/engagements/${e.id}/transition`, red, { to: 'active' });

    expect(
      (await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, { technique: 'web_scan' }))
        .status,
    ).toBe(409); // not in scope
    const noWorker = await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
      technique: 'vulnerability_scan',
    });
    expect(noWorker.status).toBe(409);
    expect((await jsonOf(noWorker)).error.message).toMatch(/No worker/);
    expect(
      (
        await post(`/api/v1/assessments/engagements/${e.id}/runs`, auditor, {
          technique: 'host_discovery',
        })
      ).status,
    ).toBe(403);

    // Dry run: every target gets a scope decision, nothing is sent, no findings.
    const dry = AssessmentRun.parse(
      await jsonOf(
        await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
          technique: 'service_fingerprint',
          ports: [1],
        }),
      ),
    );
    expect(dry).toMatchObject({ status: 'queued', dryRun: true, targetCount: 1 });
    const dryDone = AssessmentRun.parse(
      await jsonOf(await post(`/api/v1/assessments/runs/${dry.id}/execute`, red)),
    );
    expect(dryDone).toMatchObject({
      status: 'completed',
      summary: { allowed: 1, skipped: 1, reachable: 0, findingsCreated: 0 },
    });
    expect((await post(`/api/v1/assessments/runs/${dry.id}/execute`, red)).status).toBe(409); // not queued any more

    // Real run against a loopback listener on a risky port → reachable, finding created, inventory observation.
    const { server, port } = await listenRisky();
    try {
      const run = AssessmentRun.parse(
        await jsonOf(
          await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
            technique: 'service_fingerprint',
            dryRun: false,
            ports: [port, 1],
          }),
        ),
      );
      const done = AssessmentRun.parse(
        await jsonOf(await post(`/api/v1/assessments/runs/${run.id}/execute`, red)),
      );
      expect(done.summary).toMatchObject({
        allowed: 1,
        reachable: 1,
        findingsCreated: 1,
        findingsUpdated: 0,
      });
      const detail = RunDetail.parse(
        await jsonOf(await get(`/api/v1/assessments/runs/${run.id}`, auditor)),
      );
      expect(detail.targets[0]).toMatchObject({
        decision: 'allowed',
        outcome: 'reachable',
        openPorts: [port],
      });
      expect(detail.findings).toHaveLength(1);
      const f = detail.findings[0]!;
      expect(f).toMatchObject({ status: 'open', validated: true, engagementId: e.id });
      expect(f.title).toMatch(new RegExp(`tcp/${port}$`));
      // Second run updates the same finding instead of duplicating it.
      const again = AssessmentRun.parse(
        await jsonOf(
          await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
            technique: 'service_fingerprint',
            dryRun: false,
            ports: [port],
          }),
        ),
      );
      const againDone = AssessmentRun.parse(
        await jsonOf(await post(`/api/v1/assessments/runs/${again.id}/execute`, red)),
      );
      expect(againDone.summary).toMatchObject({ findingsCreated: 0, findingsUpdated: 1 });
      const list = await jsonOf(await get(`/api/v1/findings?engagementId=${e.id}`, vuln));
      expect(list.items).toHaveLength(1);
      // Triage: analysts manage, auditors read; the triage status survives later observations.
      expect(
        (
          await h.app.request(`/api/v1/findings/${f.id}`, {
            method: 'PATCH',
            headers: authed(auditor),
            body: JSON.stringify({ status: 'accepted_risk', note: 'x' }),
          })
        ).status,
      ).toBe(403);
      const triaged = FindingRecord.parse(
        await jsonOf(
          await h.app.request(`/api/v1/findings/${f.id}`, {
            method: 'PATCH',
            headers: authed(vuln),
            body: JSON.stringify({
              status: 'accepted_risk',
              note: 'Lab cache; isolated VLAN, no data',
            }),
          }),
        ),
      );
      expect(triaged).toMatchObject({
        status: 'accepted_risk',
        lastNote: 'Lab cache; isolated VLAN, no data',
      });
      const third = AssessmentRun.parse(
        await jsonOf(
          await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
            technique: 'service_fingerprint',
            dryRun: false,
            ports: [port],
          }),
        ),
      );
      await post(`/api/v1/assessments/runs/${third.id}/execute`, red);
      expect(
        (await jsonOf(await get(`/api/v1/findings?engagementId=${e.id}`, vuln))).items[0].status,
      ).toBe('accepted_risk');
      expect(e.runCount).toBe(0);
      expect(
        (await jsonOf(await get(`/api/v1/assessments/engagements/${e.id}`, auditor))).runCount,
      ).toBe(4);

      // Report: coverage from the run records, findings for findings.read holders, limitations always.
      const report = EngagementReport.parse(
        await jsonOf(await get(`/api/v1/assessments/engagements/${e.id}/report`, vuln)),
      );
      expect(report.runs).toHaveLength(4);
      expect(report.coverage).toMatchObject({
        targetsInScope: 1,
        assessedWithFindings: 1,
        notAssessed: 0,
        truncated: false,
      });
      expect(report.targets[0]).toMatchObject({
        status: 'assessed_with_findings',
        findingCount: 1,
        outsideCurrentScope: false,
      });
      expect(report.targets[0]!.openPorts).toContain(port);
      expect(report.targets[0]!.techniques).toContain('service_fingerprint');
      expect(report.techniques.find((x) => x.technique === 'service_fingerprint')).toMatchObject({
        executable: true,
        status: 'performed',
      });
      expect(report.findingsIncluded).toBe(true);
      expect(report.findings).toHaveLength(1);
      expect(report.limitations.join('\n')).toMatch(/connect-level/);
      expect(report.limitations.join('\n')).toMatch(/interim report/);
      const md = await get(`/api/v1/assessments/engagements/${e.id}/report?format=markdown`, vuln);
      expect(md.headers.get('content-type')).toMatch(/text\/markdown/);
      const text = await md.text();
      expect(text).toContain(`# Assessment report — ${e.reference}`);
      expect(text).toContain(`tcp/${port}`);
      // Without findings.read the findings are withheld and the report says so.
      const withheld = EngagementReport.parse(
        await jsonOf(await get(`/api/v1/assessments/engagements/${e.id}/report`, blue)),
      );
      expect(withheld.findingsIncluded).toBe(false);
      expect(withheld.findings).toHaveLength(0);
      expect(withheld.limitations.join('\n')).toMatch(/withheld/i);
      expect(
        (
          await get(
            `/api/v1/assessments/engagements/00000000-0000-4000-8000-00000000dead/report`,
            vuln,
          )
        ).status,
      ).toBe(404);
      const audit = await jsonOf(await get('/api/v1/audit?limit=100', admin.token));
      expect(
        audit.items.filter((x: { action: string }) => x.action === 'assessments.report'),
      ).toHaveLength(3); // JSON, Markdown and the withheld one: every export is audited
    } finally {
      server.close();
    }

    // Worker policy: a scope whose target is outside a discovery-allowed segment is refused at run creation.
    const mgmt = EngagementRecord.parse(
      await jsonOf(
        await post(
          '/api/v1/assessments/engagements',
          red,
          engagement({ reference: 'ENG-MGMT', scope: scope({ includeAddresses: ['10.99.0.5'] }) }),
        ),
      ),
    );
    await post(`/api/v1/assessments/engagements/${mgmt.id}/transition`, red, {
      to: 'pending_approval',
    });
    await post(`/api/v1/assessments/engagements/${mgmt.id}/approve`, sec, {
      justification: 'Authorised by contract; mgmt range',
    });
    await post(`/api/v1/assessments/engagements/${mgmt.id}/transition`, red, { to: 'active' });
    const refused = await post(`/api/v1/assessments/engagements/${mgmt.id}/runs`, red, {
      technique: 'host_discovery',
    });
    expect(refused.status).toBe(422);
    expect((await jsonOf(refused)).error.message).toMatch(/segment/);

    // Window expiry ends the engagement on its own and cancels queued runs.
    const queued = AssessmentRun.parse(
      await jsonOf(
        await post(`/api/v1/assessments/engagements/${e.id}/runs`, red, {
          technique: 'host_discovery',
        }),
      ),
    );
    await h.handle.db.execute(
      sql`update assessment_scopes set window_end = now() - interval '1 second' where engagement_id = ${e.id}`,
    );
    expect(
      (await jsonOf(await get(`/api/v1/assessments/engagements/${e.id}`, auditor))).status,
    ).toBe('expired');
    expect(
      (await jsonOf(await get(`/api/v1/assessments/runs/${queued.id}`, auditor))).run.status,
    ).toBe('cancelled');
    expect((await post(`/api/v1/assessments/runs/${queued.id}/execute`, red)).status).toBe(409);
  });
});
