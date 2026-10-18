import type { Context, MiddlewareHandler } from 'hono';
import { randomUUID } from 'node:crypto';
import { getConnInfo } from '@hono/node-server/conninfo';
import type { Logger } from 'pino';
import type { Permission, RoleKey } from '@noc/shared';
import type { Env } from '../config/env';

export interface Principal {
  userId: string;
  email: string;
  displayName: string;
  roles: RoleKey[];
  permissions: Set<Permission>;
  tokenJti: string;
}

export interface SensorPrincipal {
  sensorId: string;
  name: string;
  kind: string;
  hostAssetId: string | null;
}

export type AppEnv = {
  Variables: {
    requestId: string;
    log: Logger;
    clientIp: string | null;
    principal: Principal | null;
    sensor: SensorPrincipal | null;
  };
};

const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/;

export function clientIpOf(c: Context<AppEnv>, env: Env): string | null {
  if (env.TRUST_PROXY) {
    const xff = c.req.header('x-forwarded-for');
    const first = xff?.split(',')[0]?.trim();
    if (first) return first;
  }
  try {
    const info = getConnInfo(c);
    return info.remote.address ?? null;
  } catch {
    return null; // in-process testing via app.request() has no socket
  }
}

export function requestContext(env: Env, baseLogger: Logger): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const incoming = c.req.header('x-request-id');
    const requestId =
      env.TRUST_PROXY && incoming && SAFE_REQUEST_ID.test(incoming) ? incoming : randomUUID();
    const clientIp = clientIpOf(c, env);
    const log = baseLogger.child({ requestId });
    c.set('requestId', requestId);
    c.set('clientIp', clientIp);
    c.set('log', log);
    c.set('principal', null);
    c.set('sensor', null);
    c.header('X-Request-Id', requestId);

    const started = process.hrtime.bigint();
    try {
      await next();
    } finally {
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      const principal = c.get('principal');
      log.info(
        {
          method: c.req.method,
          path: c.req.path,
          status: c.res.status,
          durationMs: Math.round(durationMs * 100) / 100,
          userId: principal?.userId ?? null,
          ip: clientIp,
        },
        'request',
      );
    }
  };
}
