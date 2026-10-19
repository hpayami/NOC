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
    /** Analysis service (advisory ML). Unreachable is a reported state, not a startup failure. */
    ANALYSIS_URL: z.string().url().default('http://127.0.0.1:8000'),
    ANALYSIS_INTERNAL_TOKEN: z.string().min(24).optional(),
    /** OIDC SSO (authorization code + PKCE). Enabled only when issuer, client id and redirect URI are all set. */
    OIDC_ISSUER: z.string().url().optional(),
    OIDC_CLIENT_ID: z.string().min(1).optional(),
    OIDC_CLIENT_SECRET: z.string().min(8).optional(),
    OIDC_REDIRECT_URI: z.string().url().optional(),
    OIDC_SCOPES: z.string().default('openid profile email'),
    OIDC_ROLE_CLAIM: z.string().default('groups'),
    /** JSON object: IdP group/role value → platform role key. */
    OIDC_ROLE_MAP: z.string().default('{}'),
    OIDC_DEFAULT_ROLES: z.string().optional(),
    OIDC_ALLOW_JIT: bool.default(true),
    OIDC_AUTO_LINK_BY_EMAIL: bool.default(false),
    OIDC_DISPLAY_NAME: z.string().max(64).default('Single sign-on'),
    /** Enables RP-initiated logout: where the IdP sends the browser after ending its session. */
    OIDC_POST_LOGOUT_REDIRECT_URI: z.string().url().optional(),
    /** Shared rate-limit store for multi-instance deployments; unset = per-instance limits. */
    REDIS_URL: z.string().url().optional(),
    /** Inline-prevention watchdog: returns sensors to detect-only when they stop qualifying. */
    IPS_WATCHDOG_ENABLED: bool.default(true),
    IPS_WATCHDOG_INTERVAL_SECONDS: z.coerce.number().int().min(10).max(600).default(60),
    /** Platform-condition notifications (signed webhooks). */
    NOTIFICATIONS_ENABLED: bool.default(true),
    NOTIFICATIONS_INTERVAL_SECONDS: z.coerce.number().int().min(30).max(3600).default(120),
    NOTIFICATIONS_REMIND_HOURS: z.coerce.number().int().min(1).max(168).default(6),
    VALIDATION_SCHEDULER_ENABLED: bool.default(true),
    VALIDATION_SCHEDULER_INTERVAL_SECONDS: z.coerce.number().int().min(60).max(86_400).default(300),
    RETENTION_ENABLED: bool.default(true),
    RETENTION_INTERVAL_MINUTES: z.coerce.number().int().min(5).max(1440).default(60),
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
