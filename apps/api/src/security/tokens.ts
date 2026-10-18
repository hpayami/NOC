import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import type { RoleKey } from '@noc/shared';

const ISSUER = 'noc-api';
const AUDIENCE = 'noc-platform';

export interface AccessClaims {
  sub: string;
  roles: RoleKey[];
  /** token version at issue time; compared to users.token_version on every request */
  tv: number;
  jti: string;
  exp: number;
}

export class TokenService {
  private readonly key: Uint8Array;
  constructor(
    secret: string,
    private readonly accessTtlSeconds: number,
  ) {
    this.key = new TextEncoder().encode(secret);
  }

  async issueAccessToken(input: {
    userId: string;
    roles: RoleKey[];
    tokenVersion: number;
  }): Promise<{ token: string; expiresIn: number }> {
    const token = await new SignJWT({ roles: input.roles, tv: input.tokenVersion })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(input.userId)
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${this.accessTtlSeconds}s`)
      .sign(this.key);
    return { token, expiresIn: this.accessTtlSeconds };
  }

  async verifyAccessToken(token: string): Promise<AccessClaims | null> {
    try {
      const { payload } = await jwtVerify(token, this.key, {
        issuer: ISSUER,
        audience: AUDIENCE,
        algorithms: ['HS256'],
        clockTolerance: 5,
      });
      if (
        typeof payload.sub !== 'string' ||
        typeof payload.tv !== 'number' ||
        !Array.isArray(payload.roles)
      )
        return null;
      return {
        sub: payload.sub,
        roles: payload.roles as RoleKey[],
        tv: payload.tv,
        jti: String(payload.jti),
        exp: Number(payload.exp),
      };
    } catch (err) {
      if (err instanceof joseErrors.JOSEError) return null;
      throw err;
    }
  }
}

/** Opaque refresh token: 256 bits of randomness, base64url; only its SHA-256 is persisted. */
export function generateRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: hashRefreshToken(token) };
}

export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
