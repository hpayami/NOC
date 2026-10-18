import pino from 'pino';
import { sql } from 'drizzle-orm';
import { createApp, type App } from '../src/app';
import { AuditService } from '../src/audit/service';
import { AlertBus } from '../src/events/bus';
import { loadEnv, type Env } from '../src/config/env';
import { createDb, type DbHandle } from '../src/db/client';
import { RateLimiter } from '../src/middleware/rate-limit';
import { createMetrics } from '../src/platform/metrics';
import { RetentionService } from '../src/retention/service';
import { syncRbacCatalog } from '../src/platform/seed';
import { TokenService } from '../src/security/tokens';
import { bootstrapAdmin } from '../scripts/bootstrap-admin';
import { runMigrations } from '../scripts/migrate';

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
if (!TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL is required for API integration tests');
if (!/noc_test|_test\b/.test(TEST_DATABASE_URL))
  throw new Error('TEST_DATABASE_URL must point at a *_test database');

export const ADMIN = {
  email: 'admin@test.local',
  displayName: 'Test Admin',
  password: 'correct-horse-battery-staple-42',
};

export interface Harness {
  app: App;
  handle: DbHandle;
  env: Env;
  limiter: RateLimiter;
  close: () => Promise<void>;
}

export async function createHarness(
  envOverrides: Partial<NodeJS.ProcessEnv> = {},
): Promise<Harness> {
  const env = loadEnv({
    NODE_ENV: 'test',
    DATABASE_URL: TEST_DATABASE_URL,
    AUTH_JWT_SECRET: 'test-secret-that-is-definitely-long-enough-0123456789',
    CORS_ALLOWED_ORIGINS: 'http://localhost:3000',
    LOG_LEVEL: 'silent',
    METRICS_TOKEN: 'metrics-token-for-tests-0123456789',
    ...envOverrides,
  });
  await runMigrations(env.DATABASE_URL, { quiet: true });
  const handle = createDb(env.DATABASE_URL, { max: 4 });
  await resetDatabase(handle);
  await syncRbacCatalog(handle.db);
  const limiter = new RateLimiter();
  const audit = new AuditService(handle.db);
  const app = createApp({
    env,
    db: handle.db,
    logger: pino({ level: 'silent' }),
    tokens: new TokenService(env.AUTH_JWT_SECRET, env.AUTH_ACCESS_TTL_SECONDS),
    audit,
    limiter,
    metrics: createMetrics(),
    bus: new AlertBus(),
    retention: new RetentionService(handle.db, audit, { batchSize: 2, maxBatchesPerDataset: 3 }),
  });
  return { app, handle, env, limiter, close: () => handle.close() };
}

export async function resetDatabase(handle: DbHandle): Promise<void> {
  await handle.db.execute(
    sql`truncate table users, refresh_tokens, audit_events, assets, sensors, alerts, incidents, retention_policies restart identity cascade`,
  );
}

export async function seedAdmin(h: Harness): Promise<{ id: string }> {
  return bootstrapAdmin(h.handle.db, ADMIN);
}

export async function login(h: Harness, email: string, password: string) {
  const res = await h.app.request('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
    body: JSON.stringify({ email, password }),
  });
  const body = (await res.json().catch(() => null)) as any;
  const setCookie = res.headers.get('set-cookie') ?? '';
  const refresh = /noc_refresh=([^;]+)/.exec(setCookie)?.[1] ?? null;
  return { res, body, refresh, setCookie };
}

export async function loginAdmin(h: Harness) {
  const r = await login(h, ADMIN.email, ADMIN.password);
  if (r.res.status !== 200)
    throw new Error(`admin login failed: ${r.res.status} ${JSON.stringify(r.body)}`);
  return { token: r.body.accessToken as string, refresh: r.refresh!, user: r.body.user };
}

/** Test-only: parse a JSON response body without fighting `unknown`. */
export const jsonOf = async (res: Response): Promise<any> => (await res.json()) as any;

export function authed(token: string, extra: Record<string, string> = {}) {
  return {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
    origin: 'http://localhost:3000',
    ...extra,
  };
}

export async function createUser(
  h: Harness,
  adminToken: string,
  input: { email: string; password: string; roles: string[]; displayName?: string },
) {
  const res = await h.app.request('/api/v1/users', {
    method: 'POST',
    headers: authed(adminToken),
    body: JSON.stringify({
      email: input.email,
      displayName: input.displayName ?? input.email,
      password: input.password,
      roles: input.roles,
    }),
  });
  return { res, body: await jsonOf(res) };
}
