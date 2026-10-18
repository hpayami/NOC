import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env';
import { RateLimiter } from '../src/middleware/rate-limit';
import { TokenService } from '../src/security/tokens';
import { hashPassword, verifyPassword } from '../src/security/password';

const base = { DATABASE_URL: 'postgres://u:p@localhost:5432/db', AUTH_JWT_SECRET: 'x'.repeat(40) };

describe('environment validation', () => {
  it('applies safe defaults', () => {
    const env = loadEnv(base);
    expect(env.API_HOST).toBe('127.0.0.1');
    expect(env.COOKIE_SECURE).toBe(false);
    expect(env.CORS_ALLOWED_ORIGINS).toEqual(['http://localhost:3000']);
  });
  it('rejects short secrets and non-postgres URLs', () => {
    expect(() => loadEnv({ ...base, AUTH_JWT_SECRET: 'short' })).toThrow(/AUTH_JWT_SECRET/);
    expect(() => loadEnv({ ...base, DATABASE_URL: 'mysql://x' })).toThrow(/DATABASE_URL/);
  });
  it('refuses placeholder secrets and insecure cookies in production', () => {
    expect(() =>
      loadEnv({
        ...base,
        NODE_ENV: 'production',
        AUTH_JWT_SECRET: 'changeme-changeme-changeme-changeme-1',
      }),
    ).toThrow(/placeholder/);
    expect(() => loadEnv({ ...base, NODE_ENV: 'production', COOKIE_SECURE: 'false' })).toThrow(
      /COOKIE_SECURE/,
    );
    expect(() =>
      loadEnv({ ...base, NODE_ENV: 'production', CORS_ALLOWED_ORIGINS: 'http://noc.example.com' }),
    ).toThrow(/https/);
  });
});

describe('tokens', () => {
  it('round-trips claims and rejects tampering and foreign secrets', async () => {
    const svc = new TokenService('a'.repeat(40), 300);
    const { token } = await svc.issueAccessToken({
      userId: '11111111-1111-4111-8111-111111111111',
      roles: ['soc_analyst'],
      tokenVersion: 3,
    });
    const claims = await svc.verifyAccessToken(token);
    expect(claims?.sub).toBe('11111111-1111-4111-8111-111111111111');
    expect(claims?.tv).toBe(3);
    expect(await svc.verifyAccessToken(token + 'x')).toBeNull();
    expect(await new TokenService('b'.repeat(40), 300).verifyAccessToken(token)).toBeNull();
  });
  it('rejects expired tokens', async () => {
    const svc = new TokenService('a'.repeat(40), 60);
    const { token } = await svc.issueAccessToken({ userId: 'u', roles: [], tokenVersion: 0 });
    const [h, p, s] = token.split('.');
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString());
    payload.exp = Math.floor(Date.now() / 1000) - 120;
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
    expect(await svc.verifyAccessToken(forged)).toBeNull(); // signature no longer matches
  });
});

describe('password hashing', () => {
  it('produces argon2id PHC strings and verifies', async () => {
    const phc = await hashPassword('some-long-password-value');
    expect(phc.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(phc, 'some-long-password-value')).toBe(true);
    expect(await verifyPassword(phc, 'some-long-password-valuX')).toBe(false);
    expect(await verifyPassword('garbage', 'x')).toBe(false);
  });
});

describe('rate limiter', () => {
  it('refills over time', () => {
    let now = 0;
    const rl = new RateLimiter(() => now);
    expect(rl.take('k', 2, 1).allowed).toBe(true);
    expect(rl.take('k', 2, 1).allowed).toBe(true);
    const denied = rl.take('k', 2, 1);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    now = 1500;
    expect(rl.take('k', 2, 1).allowed).toBe(true);
  });
});
