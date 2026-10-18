import { serve } from '@hono/node-server';
import pino from 'pino';
import { createApp } from './app';
import { AuditService } from './audit/service';
import { OidcService, oidcConfigFromEnv } from './auth/oidc';
import { loadEnv } from './config/env';
import { createDb } from './db/client';
import { RateLimiter } from './middleware/rate-limit';
import { RedisRateLimiter } from './middleware/redis-limiter';
import { AlertBus } from './events/bus';
import { RedisAlertBus } from './events/redis-bus';
import { AvailabilityService, MonitoringScheduler } from './monitoring/service';
import { createMetrics } from './platform/metrics';
import { syncRbacCatalog } from './platform/seed';
import { IpsService, IpsWatchdog } from './ips/service';
import { MlService } from './ml/service';
import { NotificationScheduler, OperationsService } from './operations/service';
import { RetentionScheduler, RetentionService } from './retention/service';
import { TokenService } from './security/tokens';

async function main() {
  const env = loadEnv();
  const logger = pino({
    level: env.LOG_LEVEL,
    base: { service: 'noc-api', version: env.APP_VERSION },
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        '*.password',
        '*.passwordHash',
        '*.accessToken',
      ],
      censor: '[redacted]',
    },
  });

  const handle = createDb(env.DATABASE_URL, { max: env.DATABASE_POOL_MAX });
  await syncRbacCatalog(handle.db);

  const audit = new AuditService(handle.db);
  const retention = new RetentionService(handle.db, audit);
  await retention.ensureDefaults();
  const ml = new MlService(handle.db, audit, logger, {
    url: env.ANALYSIS_URL,
    token: env.ANALYSIS_INTERNAL_TOKEN ?? null,
  });
  const deps = {
    env,
    db: handle.db,
    logger,
    tokens: new TokenService(env.AUTH_JWT_SECRET, env.AUTH_ACCESS_TTL_SECONDS),
    audit,
    limiter: env.REDIS_URL ? new RedisRateLimiter(env.REDIS_URL, logger) : new RateLimiter(),
    metrics: createMetrics(),
    bus: env.REDIS_URL ? new RedisAlertBus(env.REDIS_URL, logger) : new AlertBus(),
    retention,
    ips: new IpsService(handle.db, audit),
    ml,
    oidc: new OidcService(handle.db, audit, oidcConfigFromEnv(env)),
    operations: new OperationsService(handle.db, audit, ml, {
      version: env.APP_VERSION,
      remindHours: env.NOTIFICATIONS_REMIND_HOURS,
      logger,
    }),
  };
  const app = createApp(deps);

  const scheduler = new MonitoringScheduler(handle.db, new AvailabilityService(handle.db), {
    tickSeconds: env.MONITORING_TICK_SECONDS,
    maxConcurrency: env.MONITORING_MAX_CONCURRENCY,
    logger,
  });
  if (env.MONITORING_SCHEDULER_ENABLED) scheduler.start();
  const retentionScheduler = new RetentionScheduler(retention, {
    intervalMinutes: env.RETENTION_INTERVAL_MINUTES,
    logger,
  });
  if (env.RETENTION_ENABLED) retentionScheduler.start();
  const ipsWatchdog = new IpsWatchdog(deps.ips, {
    intervalSeconds: env.IPS_WATCHDOG_INTERVAL_SECONDS,
    logger,
  });
  if (env.IPS_WATCHDOG_ENABLED) ipsWatchdog.start();
  const notifications = new NotificationScheduler(deps.operations, {
    intervalSeconds: env.NOTIFICATIONS_INTERVAL_SECONDS,
    logger,
  });
  if (env.NOTIFICATIONS_ENABLED) notifications.start();

  const server = serve({ fetch: app.fetch, hostname: env.API_HOST, port: env.API_PORT }, (info) => {
    logger.info({ host: info.address, port: info.port, env: env.NODE_ENV }, 'noc-api listening');
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'shutting down');
    scheduler.stop();
    retentionScheduler.stop();
    ipsWatchdog.stop();
    notifications.stop();
    if (deps.bus instanceof RedisAlertBus) deps.bus.close();
    if (deps.limiter instanceof RedisRateLimiter) deps.limiter.close();
    server.close();
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err) => {
  // Logger may not exist yet (env validation failed); stderr is the only safe sink.
  process.stderr.write(`[noc-api] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
