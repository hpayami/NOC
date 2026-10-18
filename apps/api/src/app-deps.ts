import type { Logger } from 'pino';
import type { AuditService } from './audit/service';
import type { AlertBus } from './events/bus';
import type { Env } from './config/env';
import type { Db } from './db/client';
import type { RateLimiter } from './middleware/rate-limit';
import type { Metrics } from './platform/metrics';
import type { TokenService } from './security/tokens';

export interface Deps {
  env: Env;
  db: Db;
  logger: Logger;
  tokens: TokenService;
  audit: AuditService;
  limiter: RateLimiter;
  metrics: Metrics;
  bus: AlertBus;
}
