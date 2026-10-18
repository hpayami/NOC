import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { RetentionPolicy, RetentionRunReport } from '@noc/shared';
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
let admin: { token: string }; // platform_admin: retention.read only
let secadmin: string; // security_admin: retention.modify
const PW = 'retention-password-that-is-long-enough';

beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await resetDatabase(h.handle);
  await h.handle.db.execute(
    sql`truncate table security_events, sensor_health, check_results, asset_metrics, asset_observations cascade`,
  );
  h.limiter.reset();
  await seedAdmin(h);
  admin = await loginAdmin(h);
  await createUser(h, admin.token, {
    email: 'sec@test.local',
    password: PW,
    roles: ['security_admin'],
  });
  secadmin = (await login(h, 'sec@test.local', PW)).body.accessToken;
});

const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000);

async function seedEvents(count: number, at: Date, incidentId: string | null = null) {
  for (let i = 0; i < count; i++)
    await h.handle.db.execute(sql`
      insert into security_events (id, schema_version, event_time, source_product, category, type, severity, dedup_hash, incident_id)
      values (gen_random_uuid(), '1.0', ${at.toISOString()}::timestamptz, 'suricata', 'network', 'flow', 'info', ${`h-${at.getTime()}-${i}-${incidentId ?? 'x'}`}, ${incidentId})`);
}

describe('retention policies and enforcement', () => {
  it('exposes defaults, enforces the audit floor and separates read from modify', async () => {
    const list = await jsonOf(
      await h.app.request('/api/v1/retention', { headers: authed(admin.token) }),
    );
    const items = list.items.map((p: unknown) => RetentionPolicy.parse(p));
    expect(items.map((p: RetentionPolicy) => p.dataClass)).toEqual([
      'security_events',
      'raw_events',
      'flows',
      'audit',
      'evidence',
      'metrics',
      'observations',
      'pcap',
    ]);
    expect(items.find((p: RetentionPolicy) => p.dataClass === 'audit')?.retentionDays).toBe(365);
    expect(list.lastRun).toBeNull();
    // platform_admin may read but not modify; security_admin modifies (audited).
    expect(
      (
        await h.app.request('/api/v1/retention/security_events', {
          method: 'PUT',
          headers: authed(admin.token),
          body: JSON.stringify({ retentionDays: 10 }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await h.app.request('/api/v1/retention/audit', {
          method: 'PUT',
          headers: authed(secadmin),
          body: JSON.stringify({ retentionDays: 30 }),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await h.app.request('/api/v1/retention/nonsense', {
          method: 'PUT',
          headers: authed(secadmin),
          body: JSON.stringify({ retentionDays: 30 }),
        })
      ).status,
    ).toBe(400);
    const upd = await jsonOf(
      await h.app.request('/api/v1/retention/security_events', {
        method: 'PUT',
        headers: authed(secadmin),
        body: JSON.stringify({ retentionDays: 10, legalHold: false }),
      }),
    );
    expect(upd).toMatchObject({
      dataClass: 'security_events',
      retentionDays: 10,
      legalHold: false,
    });
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=20', { headers: authed(admin.token) }),
    );
    const e = audit.items.find((x: { action: string }) => x.action === 'retention.modify');
    expect(e.metadata).toMatchObject({
      dataClass: 'security_events',
      from: { retentionDays: 30 },
      to: { retentionDays: 10 },
    });
  });

  it('purges only rows past the cutoff, keeps incident evidence, honours legal hold and bounds each run', async () => {
    await seedEvents(3, daysAgo(40)); // old, purgeable
    await seedEvents(2, daysAgo(1)); // fresh
    // security_admin cannot open incidents; insert the incident row directly for the evidence check.
    const [row] = (await h.handle.db.execute(
      sql`insert into incidents (title, severity) values ('evidence holder', 'low') returning id`,
    )) as unknown as Array<{ id: string }>;
    const incidentId = row!.id;
    await seedEvents(2, daysAgo(40), incidentId); // old but attached to an incident → kept

    const report = RetentionRunReport.parse(
      await jsonOf(
        await h.app.request('/api/v1/retention/run', { method: 'POST', headers: authed(secadmin) }),
      ),
    );
    const se = report.datasets.find((d) => d.dataset === 'security_events')!;
    expect(se).toMatchObject({ dataClass: 'security_events', deleted: 3, outcome: 'purged' });
    expect(report.datasets.find((d) => d.dataClass === 'audit')).toMatchObject({
      outcome: 'protected',
      deleted: 0,
    });
    expect(report.datasets.find((d) => d.dataClass === 'pcap')).toMatchObject({
      outcome: 'dataset_absent',
      deleted: 0,
    });
    expect(report.totalDeleted).toBe(3);
    const counted = (await h.handle.db.execute(
      sql`select count(*)::int as n from security_events`,
    )) as unknown as Array<{ n: number }>;
    expect(counted[0]!.n).toBe(4); // 2 fresh + 2 incident-attached

    // Legal hold: nothing is deleted for that class even when past the cutoff.
    await h.app.request('/api/v1/retention/security_events', {
      method: 'PUT',
      headers: authed(secadmin),
      body: JSON.stringify({ retentionDays: 1, legalHold: true }),
    });
    await seedEvents(1, daysAgo(5));
    const held = RetentionRunReport.parse(
      await jsonOf(
        await h.app.request('/api/v1/retention/run', { method: 'POST', headers: authed(secadmin) }),
      ),
    );
    expect(held.datasets.find((d) => d.dataset === 'security_events')).toMatchObject({
      outcome: 'legal_hold',
      deleted: 0,
    });

    // Bounded run: the test harness uses batchSize 2 × 3 batches = 6 rows max per dataset per run.
    await h.app.request('/api/v1/retention/security_events', {
      method: 'PUT',
      headers: authed(secadmin),
      body: JSON.stringify({ retentionDays: 7, legalHold: false }),
    });
    await seedEvents(8, daysAgo(10));
    const bounded = RetentionRunReport.parse(
      await jsonOf(
        await h.app.request('/api/v1/retention/run', { method: 'POST', headers: authed(secadmin) }),
      ),
    );
    expect(bounded.datasets.find((d) => d.dataset === 'security_events')).toMatchObject({
      outcome: 'truncated',
      deleted: 6,
    });
    const again = RetentionRunReport.parse(
      await jsonOf(
        await h.app.request('/api/v1/retention/run', { method: 'POST', headers: authed(secadmin) }),
      ),
    );
    expect(again.datasets.find((d) => d.dataset === 'security_events')).toMatchObject({
      outcome: 'purged',
      deleted: 2,
    });
    const overview = await jsonOf(
      await h.app.request('/api/v1/retention', { headers: authed(admin.token) }),
    );
    expect(overview.lastRun.trigger).toBe('manual');
    const audit = await jsonOf(
      await h.app.request('/api/v1/audit?limit=50', { headers: authed(admin.token) }),
    );
    expect(
      audit.items.filter((x: { action: string }) => x.action === 'retention.run').length,
    ).toBeGreaterThanOrEqual(4);
  });
});
