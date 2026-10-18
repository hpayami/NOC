import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { eq } from 'drizzle-orm';
import type { Permission, RoleKey } from '@noc/shared';
import type { Db } from '../db/client';
import { rolePermissions, sensors, userRoles, users } from '../db/schema';
import type { TokenService } from '../security/tokens';
import type { AppEnv, Principal } from './context';
import { hashesMatch } from '../agents/service';

export function unauthorized(message = 'Authentication required'): HTTPException {
  return new HTTPException(401, { message });
}
export function forbidden(message = 'Insufficient permissions'): HTTPException {
  return new HTTPException(403, { message });
}

/** Loads a live principal (roles, permissions, status) from the database — tokens carry no permissions. */
export async function loadPrincipal(
  db: Db,
  userId: string,
  tokenVersion: number,
  jti: string,
): Promise<Principal | null> {
  const [u] = await db
    .select({
      id: users.id,
      email: users.email,
      displayName: users.displayName,
      status: users.status,
      tokenVersion: users.tokenVersion,
    })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  if (!u || u.status !== 'active' || u.tokenVersion !== tokenVersion) return null;

  const rows = await db
    .select({ roleKey: userRoles.roleKey, permissionKey: rolePermissions.permissionKey })
    .from(userRoles)
    .leftJoin(rolePermissions, eq(rolePermissions.roleKey, userRoles.roleKey))
    .where(eq(userRoles.userId, userId));

  const roles = new Set<RoleKey>();
  const permissions = new Set<Permission>();
  for (const r of rows) {
    roles.add(r.roleKey as RoleKey);
    if (r.permissionKey) permissions.add(r.permissionKey as Permission);
  }
  return {
    userId: u.id,
    email: u.email,
    displayName: u.displayName,
    roles: [...roles],
    permissions,
    tokenJti: jti,
  };
}

/** Parses a Bearer token when present; never fails the request by itself. */
export function authenticate(db: Db, tokens: TokenService): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const header = c.req.header('authorization');
    if (header?.startsWith('Bearer ')) {
      const raw = header.slice(7).trim();
      const claims = await tokens.verifyAccessToken(raw);
      if (claims) {
        const principal = await loadPrincipal(db, claims.sub, claims.tv, claims.jti);
        if (principal) c.set('principal', principal);
      }
    }
    await next();
  };
}

export function requireAuth(): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (!c.get('principal')) throw unauthorized();
    await next();
  };
}

/** Deny by default: every sensitive route names the permission it needs. */
export function requirePermission(...needed: Permission[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const p = c.get('principal');
    if (!p) throw unauthorized();
    const missing = needed.filter((perm) => !p.permissions.has(perm));
    if (missing.length > 0) {
      c.get('log').warn({ userId: p.userId, missing, path: c.req.path }, 'authorization denied');
      throw forbidden(`Missing permission: ${missing.join(', ')}`);
    }
    await next();
  };
}

/**
 * Sensor/agent credentials travel in `X-Sensor-Credential: <sensorId>.<secret>` and only unlock
 * the agent endpoints; they never yield a user principal.
 */
export function authenticateSensor(db: Db): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const raw = c.req.header('x-sensor-credential');
    if (raw && raw.length <= 256) {
      const dot = raw.indexOf('.');
      const sensorId = dot > 0 ? raw.slice(0, dot) : '';
      if (/^[0-9a-f-]{36}$/.test(sensorId)) {
        const [s] = await db
          .select({
            id: sensors.id,
            name: sensors.name,
            kind: sensors.kind,
            hostAssetId: sensors.hostAssetId,
            enabled: sensors.enabled,
            credentialHash: sensors.credentialHash,
          })
          .from(sensors)
          .where(eq(sensors.id, sensorId))
          .limit(1);
        if (s && s.enabled && hashesMatch(s.credentialHash, raw)) {
          c.set('sensor', {
            sensorId: s.id,
            name: s.name,
            kind: s.kind,
            hostAssetId: s.hostAssetId,
          });
        }
      }
    }
    await next();
  };
}

export function requireSensor(): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (!c.get('sensor')) throw unauthorized('Sensor credential required');
    await next();
  };
}
