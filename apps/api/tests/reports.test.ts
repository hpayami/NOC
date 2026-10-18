import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { PostureReport } from '@noc/shared';
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
let analyst: string; // soc_analyst: alerts/events/incidents/threat_intel read, no assets/audit
let responder: string; // incident_responder: incidents.close
let blue: string; // blue_team_engineer: threat_intel.manage
let cred: string;
const PW = 'reports-password-long-enough-42';

const post = (path: string, token: string, body?: unknown) =>
  h.app.request(path, {
    method: 'POST',
    headers: authed(token),
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
const get = (path: string, token: string, accept?: string) =>
  h.app.request(path, { headers: authed(token, accept ? { accept } : {}) });

async function enrol(name: string) {
  const id = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name,
        kind: 'suricata',
        site: null,
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    )
  ).id as string;
  const { token } = await jsonOf(await post(`/api/v1/sensors/${id}/enrolment-token`, admin.token));
  const c = (
    await jsonOf(
      await h.app.request('/api/v1/agents/enrol', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          enrolmentToken: token,
          hostname: name,
          platform: { os: 'Ubuntu', osVersion: '24.04', kernel: '6.8', arch: 'x86_64' },
          agentVersion: '0.1.0',
        }),
      }),
    )
  ).credential as string;
  await h.handle.db.execute(sql`update sensors set enabled = true where id = ${id}`);
  return c;
}
const at = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString();
const alertLine = (s: number, dst: string) =>
  JSON.stringify({
    timestamp: at(s),
    flow_id: 5000 + s,
    event_type: 'alert',
    src_ip: '10.20.5.9',
    src_port: 51515,
    dest_ip: dst,
    dest_port: 22,
    proto: 'TCP',
    alert: {
      action: 'allowed',
      gid: 1,
      signature_id: 2001219,
      rev: 20,
      signature: 'ET SCAN Potential SSH Scan',
      category: 'Attempted Information Leak',
      severity: 2,
    },
  });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table security_events, sensors, threat_indicators cascade`,
  );
  h.limiter.reset();
  h.threatIntel.invalidate();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['analyst@test.local', 'soc_analyst'],
    ['responder@test.local', 'incident_responder'],
    ['blue@test.local', 'blue_team_engineer'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  [analyst, responder, blue] = (await Promise.all(
    ['analyst', 'responder', 'blue'].map(
      async (u) => (await login(h, `${u}@test.local`, PW)).body.accessToken as string,
    ),
  )) as [string, string, string];
  cred = await enrol('ids-edge-1');
});

describe('posture report', () => {
  it('withholds what the reader may not see, says what is not configured, and counts only real records', async () => {
    // Analyst on an empty platform: readable planes report not_configured, the rest is withheld.
    const empty = PostureReport.parse(
      await jsonOf(await get('/api/v1/reports/posture?days=7', analyst)),
    );
    expect(empty.period.days).toBe(7);
    expect(empty.sites).toBeNull();
    expect(empty.assets).toMatchObject({
      state: 'not_configured',
      permission: 'assets.read',
      data: null,
    });
    expect(empty.prevention.state).toBe('withheld');
    expect(empty.assessments.state).toBe('withheld');
    expect(empty.governance).toMatchObject({
      state: 'withheld',
      permission: 'audit.read',
      data: null,
    });
    expect(empty.alerts).toMatchObject({ state: 'not_configured', data: null });
    expect(empty.incidents.state).toBe('not_configured');
    expect(empty.threatIntel.state).toBe('not_configured');
    expect(empty.events.state).toBe('not_configured');
    expect(empty.analytics).toMatchObject({ state: 'withheld', permission: 'ml.read' });
    expect(empty.sensors).toMatchObject({
      state: 'available',
      data: { total: 1, enabled: 1, heartbeating: 1, silent: 0 },
    });
    expect(empty.limitations.some((l) => /acknowledgement time is not tracked/i.test(l))).toBe(
      true,
    );
    expect((await get('/api/v1/reports/posture?days=0', analyst)).status).toBe(400);
    expect((await get('/api/v1/reports/posture?days=400', analyst)).status).toBe(400);

    // Activity: two detections (one tuple repeated → 1 alert bumped), an indicator hit, an incident closed.
    await post('/api/v1/threat-intel/indicators/import', blue, {
      format: 'noc',
      source: 'feed-a',
      content: JSON.stringify({
        indicators: [{ type: 'ipv4', value: '203.0.113.9', severity: 'high' }],
      }),
    });
    const ingest = await h.app.request('/api/v1/ingest/suricata/eve', {
      method: 'POST',
      headers: { 'content-type': 'application/x-ndjson', 'x-sensor-credential': cred },
      body: [
        alertLine(300, '10.20.0.2'),
        alertLine(200, '10.20.0.2'),
        alertLine(100, '203.0.113.9'),
      ].join('\n'),
    });
    expect(ingest.status).toBe(202);
    const inc = await jsonOf(
      await post('/api/v1/incidents', analyst, {
        title: 'SSH scan from 10.20.5.9',
        severity: 'high',
      }),
    );
    await post(`/api/v1/incidents/${inc.id}/transition`, analyst, { to: 'triage' });
    const closed = await post(`/api/v1/incidents/${inc.id}/transition`, responder, {
      to: 'closed',
      reason: 'Benign vulnerability scanner confirmed',
    });
    expect(closed.status).toBe(200);
    await post('/api/v1/incidents', analyst, { title: 'Still open', severity: 'medium' });

    const r = PostureReport.parse(
      await jsonOf(await get('/api/v1/reports/posture?days=30', analyst)),
    );
    expect(r.events).toMatchObject({
      state: 'available',
      data: { total: 3, sensorsReporting: 1, byCategory: { detection: 3 } },
    });
    expect(r.alerts.state).toBe('available');
    expect(r.alerts.data).toMatchObject({
      opened: 3,
      openAtEnd: 3,
      closedInPeriod: 0,
      falsePositives: 0,
      meanTimeToAcknowledgeSeconds: null,
    });
    expect(r.alerts.data!.bySeverity.high).toBe(1); // the threat-intel alert carries the indicator's severity
    expect(r.incidents.state).toBe('available');
    expect(r.incidents.data).toMatchObject({
      opened: 2,
      closed: 1,
      openAtEnd: 1,
      bySeverity: { high: 1, medium: 1 },
      byStatus: { closed: 1, new: 1 },
    });
    expect(r.incidents.data!.meanTimeToCloseSeconds).toBeGreaterThanOrEqual(0);
    expect(r.incidents.data!.medianTimeToCloseSeconds).toBe(
      r.incidents.data!.meanTimeToCloseSeconds,
    );
    expect(r.threatIntel).toMatchObject({
      state: 'available',
      data: { activeIndicators: 1, sources: 1, matchesInPeriod: 1, matchesByType: { ipv4: 1 } },
    });
    expect(r.prevention).toMatchObject({ state: 'withheld', permission: 'ips.read', data: null });

    // Admin reads the operational planes it is allowed to, and the audit plane with the chain check.
    const a = PostureReport.parse(
      await jsonOf(await get('/api/v1/reports/posture?days=30', admin.token)),
    );
    expect(a.alerts.state).toBe('withheld');
    expect(a.sensors).toMatchObject({
      state: 'available',
      data: { total: 1, enabled: 1, heartbeating: 1, silent: 0, byKind: { suricata: 1 } },
    });
    expect(a.assets).toMatchObject({ state: 'not_configured', data: null });
    expect(a.governance.state).toBe('available');
    expect(a.governance.data!.chainVerified).toBe(true);
    expect(a.governance.data!.logins).toBeGreaterThanOrEqual(4);
    expect(a.governance.data!.auditEventsInPeriod).toBeGreaterThan(0);

    // Markdown is the same report, with states written out; generation is audited for both readers.
    const md = await get(
      '/api/v1/reports/posture?days=30&format=markdown',
      analyst,
      'text/markdown',
    );
    expect(md.status).toBe(200);
    expect(md.headers.get('content-type')).toContain('text/markdown');
    const text = await md.text();
    expect(text).toContain('# Security and network posture report');
    expect(text).toContain('_Withheld: this report was generated without `ips.read`');
    expect(text).toContain('- Opened 3, closed 0 (false positives 0), open at period end 3');
    expect(text).toContain('- Matches in period 1 (ipv4 1)');
    const audit = await jsonOf(await get('/api/v1/audit?limit=50', admin.token));
    const reports = (
      audit.items as Array<{ action: string; metadata?: { withheld?: string[] } }>
    ).filter((e) => e.action === 'reports.posture');
    expect(reports.length).toBeGreaterThanOrEqual(4);
  });
});
