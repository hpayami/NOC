import { z } from 'zod';

const bool = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((v) => v === true || v === 'true' || v === '1');

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    API_HOST: z.string().min(1).default('127.0.0.1'),
    API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    DATABASE_URL: z
      .string()
      .url()
      .refine(
        (u) => u.startsWith('postgres://') || u.startsWith('postgresql://'),
        'DATABASE_URL must be a postgres URL',
      ),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
    AUTH_JWT_SECRET: z.string().min(32, 'AUTH_JWT_SECRET must be at least 32 characters'),
    AUTH_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    AUTH_REFRESH_TTL_SECONDS: z.coerce.number().int().min(300).max(2_592_000).default(28_800),
    AUTH_MAX_FAILED_LOGINS: z.coerce.number().int().min(3).max(100).default(10),
    AUTH_LOCKOUT_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
    CORS_ALLOWED_ORIGINS: z
      .string()
      .default('http://localhost:3000')
      .transform((s) =>
        s
          .split(',')
          .map((o) => o.trim())
          .filter(Boolean),
      )
      .pipe(z.array(z.string().url()).min(1)),
    COOKIE_SECURE: bool.optional(),
    TRUST_PROXY: bool.default(false),
    BODY_LIMIT_BYTES: z.coerce.number().int().min(1024).max(10_485_760).default(262_144),
    /** Engine telemetry batches are larger than API calls; still bounded. */
    INGEST_BODY_LIMIT_BYTES: z.coerce.number().int().min(65_536).max(33_554_432).default(4_194_304),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    /** Static bearer token that scrapers may use for /metrics. Optional; JWT with platform.metrics.read also works. */
    METRICS_TOKEN: z.string().min(24).optional(),
    MONITORING_SCHEDULER_ENABLED: bool.default(true),
    MONITORING_TICK_SECONDS: z.coerce.number().int().min(5).max(300).default(15),
    MONITORING_MAX_CONCURRENCY: z.coerce.number().int().min(1).max(64).default(8),
    APP_VERSION: z.string().default('0.1.0-phase1'),
  })
  .transform((e) => ({ ...e, COOKIE_SECURE: e.COOKIE_SECURE ?? e.NODE_ENV === 'production' }));

export type Env = z.infer<typeof EnvSchema>;

const PLACEHOLDER_SECRETS = ['changeme', 'change-me', 'secret', 'password', 'replace-me'];

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`);
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  const env = parsed.data;
  if (env.NODE_ENV === 'production') {
    const lower = env.AUTH_JWT_SECRET.toLowerCase();
    if (PLACEHOLDER_SECRETS.some((p) => lower.includes(p))) {
      throw new Error('AUTH_JWT_SECRET looks like a placeholder; refusing to start in production');
    }
    if (!env.COOKIE_SECURE) throw new Error('COOKIE_SECURE must be true in production');
    if (env.CORS_ALLOWED_ORIGINS.some((o) => o.startsWith('http://') && !o.includes('localhost'))) {
      throw new Error('CORS_ALLOWED_ORIGINS must use https in production');
    }
  }
  return env;
}
