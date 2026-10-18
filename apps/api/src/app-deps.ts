import type { Logger } from 'pino';
import type { AuditService } from './audit/service';
import type { OidcService } from './auth/oidc';
import type { AlertBus } from './events/bus';
import type { Env } from './config/env';
import type { IpsService } from './ips/service';
import type { MlService } from './ml/service';
import type { Db } from './db/client';
import type { RateLimiter } from './middleware/rate-limit';
import type { Metrics } from './platform/metrics';
import type { RetentionService } from './retention/service';
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
  retention: RetentionService;
  ips: IpsService;
  ml: MlService;
  oidc: OidcService;
}
