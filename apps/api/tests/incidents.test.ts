import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { IncidentDetail, IncidentStats, IncidentSummary } from '@noc/shared';
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
let analyst: string; // soc_analyst: incidents.manage, no incidents.close
let responder: string; // incident_responder: incidents.close
let auditor: string; // read_only_auditor: incidents.read only
let blue: string; // events.ingest for fixture replay
let sensorId: string;
const PW = 'incident-password-that-is-long-enough';

const EVE = (sid: number, src: string) =>
  JSON.stringify({
    timestamp: '2026-10-18T10:00:00.000000+0000',
    flow_id: 1,
    event_type: 'alert',
    src_ip: src,
    src_port: 4444,
    dest_ip: '10.0.0.5',
    dest_port: 445,
    proto: 'TCP',
    alert: {
      action: 'allowed',
      gid: 1,
      signature_id: sid,
      rev: 1,
      signature: `ET TEST ${sid}`,
      category: 'Attempted Administrator Privilege Gain',
      severity: 1,
    },
  });

async function ingestAlerts(): Promise<string[]> {
  const r = await h.app.request(`/api/v1/ingest/suricata/eve?sensorId=${sensorId}`, {
    method: 'POST',
    headers: { ...authed(blue), 'content-type': 'application/x-ndjson' },
    body: [EVE(1, '10.0.0.1'), EVE(2, '10.0.0.2'), EVE(3, '10.0.0.3')].join('\n'),
  });
  expect(r.status).toBe(202);
  const list = await jsonOf(
    await h.app.request('/api/v1/alerts?open=true', { headers: authed(analyst) }),
  );
  return list.items.map((a: { id: string }) => a.id);
}

const post = (path: string, token: string, body: unknown) =>
  h.app.request(path, { method: 'POST', headers: authed(token), body: JSON.stringify(body) });

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(sql`truncate table security_events, incident_events, sensors cascade`);
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  for (const [email, role] of [
    ['analyst@test.local', 'soc_analyst'],
    ['responder@test.local', 'incident_responder'],
    ['auditor@test.local', 'read_only_auditor'],
    ['blue@test.local', 'blue_team_engineer'],
  ] as const)
    await createUser(h, admin.token, { email, password: PW, roles: [role] });
  analyst = (await login(h, 'analyst@test.local', PW)).body.accessToken;
  responder = (await login(h, 'responder@test.local', PW)).body.accessToken;
  auditor = (await login(h, 'auditor@test.local', PW)).body.accessToken;
  blue = (await login(h, 'blue@test.local', PW)).body.accessToken;
  sensorId = (
    await jsonOf(
      await post('/api/v1/sensors', admin.token, {
        name: 'ids-1',
        kind: 'suricata',
        site: 'dc1',
        monitoredSegmentIds: [],
        engineVersion: null,
      }),
    )
  ).id;
});

describe('incident lifecycle', () => {
  it('opens an incident from alerts, escalating open ones and recording the timeline', async () => {
    const alertIds = await ingestAlerts();
    expect(alertIds).toHaveLength(3);
    // RBAC: an auditor can read but never create.
    expect(
      (await post('/api/v1/incidents', auditor, { title: 'x', severity: 'high' })).status,
    ).toBe(403);
    // Validation: unknown alert id → 404, nothing created.
    expect(
      (
        await post('/api/v1/incidents', analyst, {
          title: 'Lateral movement on 10.0.0.5',
          severity: 'high',
          alertIds: ['00000000-0000-4000-8000-000000000000'],
        })
      ).status,
    ).toBe(404);
    expect(
      (await jsonOf(await h.app.request('/api/v1/incidents/stats', { headers: authed(analyst) })))
        .total,
    ).toBe(0);

    const created = await post('/api/v1/incidents', analyst, {
      title: 'Lateral movement on 10.0.0.5',
      severity: 'high',
      summary: 'Three sources hitting SMB',
      alertIds: alertIds.slice(0, 2),
    });
    expect(created.status).toBe(201);
    const inc = IncidentSummary.parse(await jsonOf(created));
    expect(inc).toMatchObject({ status: 'new', type: 'security', severity: 'high', alertCount: 2 });
    expect(inc.assigneeId).toBeTruthy();

    const detail = IncidentDetail.parse(
      await jsonOf(
        await h.app.request(`/api/v1/incidents/${inc.id}`, { headers: authed(auditor) }),
      ),
    );
    expect(detail.alerts.map((a) => a.status)).toEqual(['escalated', 'escalated']);
    expect(detail.alerts.every((a) => a.incidentId === inc.id)).toBe(true);
    expect(detail.timeline.map((e) => e.kind)).toEqual(['opened', 'alert_linked', 'alert_linked']);
    expect(detail.incident.allowedNext).toEqual(['triage']);

    // The third alert stays untouched; linking it to a second incident is refused once attached.
    const other = await jsonOf(
      await post('/api/v1/incidents', analyst, {
        title: 'Second',
        severity: 'low',
        alertIds: [alertIds[2]],
      }),
    );
    expect(
      (await post(`/api/v1/incidents/${inc.id}/alerts`, analyst, { alertIds: [alertIds[2]] }))
        .status,
    ).toBe(409);
    // Detach, then attach to the first incident.
    expect(
      (
        await h.app.request(`/api/v1/incidents/${other.id}/alerts/${alertIds[2]}`, {
          method: 'DELETE',
          headers: authed(analyst),
        })
      ).status,
    ).toBe(204);
    const linked = await jsonOf(
      await post(`/api/v1/incidents/${inc.id}/alerts`, analyst, { alertIds: [alertIds[2]] }),
    );
    expect(linked.alertCount).toBe(3);

    const stats = IncidentStats.parse(
      await jsonOf(await h.app.request('/api/v1/incidents/stats', { headers: authed(analyst) })),
    );
    expect(stats).toMatchObject({
      total: 2,
      open: 2,
      closedLast30Days: 0,
      meanTimeToCloseSeconds: null,
    });
    expect(stats.byStatus.new).toBe(2);
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=50', { headers: authed(admin.token) }),
    );
    const actions = audit.items.map((e: { action: string }) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'incidents.create',
        'incidents.link_alerts',
        'incidents.unlink_alert',
      ]),
    );
  });

  it('walks the standard flow, enforces reasons on deviations and incidents.close on closure', async () => {
    const inc = await jsonOf(
      await post('/api/v1/incidents', analyst, {
        title: 'Ransomware note on FS-01',
        severity: 'critical',
      }),
    );
    const go = (to: string, token = analyst, reason?: string) =>
      post(`/api/v1/incidents/${inc.id}/transition`, token, { to, ...(reason ? { reason } : {}) });

    expect((await go('containment')).status).toBe(409); // skipping is not allowed
    expect((await go('new')).status).toBe(409); // same state
    expect((await jsonOf(await go('triage'))).status).toBe('triage');
    // Early closure from triage is a deviation: reason required and incidents.close required.
    expect(
      (await go('closed', analyst, 'Benign: scheduled backup job verified with owner')).status,
    ).toBe(403);
    expect((await go('closed', responder)).status).toBe(409);
    const closed = await jsonOf(
      await go('closed', responder, 'Benign: scheduled backup job verified with owner'),
    );
    expect(closed.status).toBe('closed');
    expect(closed.closedAt).toBeTruthy();
    expect(closed.closureReason).toMatch(/Benign/);
    // Closed incidents are read-only until reopened; reopening needs a reason and incidents.close.
    expect(
      (
        await h.app.request(`/api/v1/incidents/${inc.id}`, {
          method: 'PATCH',
          headers: authed(analyst),
          body: JSON.stringify({ severity: 'low' }),
        })
      ).status,
    ).toBe(409);
    expect(
      (await go('investigation', analyst, 'Recurrence observed on a second host')).status,
    ).toBe(403);
    const reopened = await jsonOf(
      await go('investigation', responder, 'Recurrence observed on a second host'),
    );
    expect(reopened).toMatchObject({
      status: 'investigation',
      closedAt: null,
      closureReason: null,
    });
    // Forward chain to closure by the responder.
    for (const to of ['containment', 'eradication', 'recovery'])
      expect((await jsonOf(await go(to, responder))).status).toBe(to);
    expect((await jsonOf(await go('closed', responder))).status).toBe('closed');

    const detail = IncidentDetail.parse(
      await jsonOf(
        await h.app.request(`/api/v1/incidents/${inc.id}`, { headers: authed(analyst) }),
      ),
    );
    const transitions = detail.timeline.filter((e) => e.kind === 'transition');
    expect(transitions.map((e) => e.toStatus)).toEqual([
      'triage',
      'closed',
      'investigation',
      'containment',
      'eradication',
      'recovery',
      'closed',
    ]);
    expect(transitions.filter((e) => e.payload.deviation === true)).toHaveLength(2);
    const stats = IncidentStats.parse(
      await jsonOf(await h.app.request('/api/v1/incidents/stats', { headers: authed(analyst) })),
    );
    expect(stats.closedLast30Days).toBe(1);
    expect(stats.meanTimeToCloseSeconds).not.toBeNull();
    // Denied closure attempt is in the audit trail.
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=100', { headers: authed(admin.token) }),
    );
    expect(
      audit.items.some(
        (e: { action: string; outcome: string }) =>
          e.action === 'incidents.transition' && e.outcome === 'denied',
      ),
    ).toBe(true);
  });

  it('supports notes, assignment, severity changes, filters and pagination', async () => {
    const a = await jsonOf(
      await post('/api/v1/incidents', analyst, { title: 'A', severity: 'low', type: 'noc_outage' }),
    );
    const b = await jsonOf(
      await post('/api/v1/incidents', analyst, { title: 'B', severity: 'medium' }),
    );
    expect((await post(`/api/v1/incidents/${a.id}/notes`, analyst, { note: '' })).status).toBe(400);
    const note = await jsonOf(
      await post(`/api/v1/incidents/${a.id}/notes`, analyst, {
        note: 'Core switch rebooted by vendor at 10:15',
      }),
    );
    expect(note).toMatchObject({ kind: 'note', note: 'Core switch rebooted by vendor at 10:15' });
    expect(
      (
        await h.app.request(`/api/v1/incidents/${a.id}`, {
          method: 'PATCH',
          headers: authed(analyst),
          body: JSON.stringify({}),
        })
      ).status,
    ).toBe(400);
    const updated = await jsonOf(
      await h.app.request(`/api/v1/incidents/${a.id}`, {
        method: 'PATCH',
        headers: authed(responder),
        body: JSON.stringify({ severity: 'high', commanderId: null, summary: 'Outage confirmed' }),
      }),
    );
    expect(updated).toMatchObject({
      severity: 'high',
      summary: 'Outage confirmed',
      commanderId: null,
    });
    const detail = IncidentDetail.parse(
      await jsonOf(await h.app.request(`/api/v1/incidents/${a.id}`, { headers: authed(analyst) })),
    );
    expect(detail.timeline.map((e) => e.kind)).toEqual([
      'opened',
      'note',
      'assignment',
      'severity_changed',
      'updated',
    ]);
    // noc_outage incidents may skip eradication from investigation (with a reason).
    await post(`/api/v1/incidents/${a.id}/transition`, analyst, { to: 'triage' });
    await post(`/api/v1/incidents/${a.id}/transition`, analyst, { to: 'investigation' });
    expect(
      (await jsonOf(await h.app.request(`/api/v1/incidents/${a.id}`, { headers: authed(analyst) })))
        .incident.allowedNext,
    ).toEqual(['containment', 'closed', 'recovery']);

    const page1 = await jsonOf(
      await h.app.request('/api/v1/incidents?limit=1', { headers: authed(auditor) }),
    );
    expect(page1.items.map((i: { id: string }) => i.id)).toEqual([b.id]);
    expect(page1.nextCursor).toBeTruthy();
    const page2 = await jsonOf(
      await h.app.request(
        `/api/v1/incidents?limit=1&cursor=${encodeURIComponent(page1.nextCursor)}`,
        { headers: authed(auditor) },
      ),
    );
    expect(page2.items.map((i: { id: string }) => i.id)).toEqual([a.id]);
    expect(page2.nextCursor).toBeNull();
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/incidents?type=noc_outage', { headers: authed(auditor) }),
        )
      ).items,
    ).toHaveLength(1);
    expect(
      (
        await jsonOf(
          await h.app.request('/api/v1/incidents?status=investigation', {
            headers: authed(auditor),
          }),
        )
      ).items.map((i: { id: string }) => i.id),
    ).toEqual([a.id]);
    expect(
      (await h.app.request('/api/v1/incidents?cursor=garbage', { headers: authed(auditor) }))
        .status,
    ).toBe(400);
  });
});
