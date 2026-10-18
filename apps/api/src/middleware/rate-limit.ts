import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { AppEnv } from './context';

interface Bucket {
  tokens: number;
  updatedAt: number;
}

/**
 * In-process token bucket. Sufficient for a single API instance (Phase 0); a Redis-backed limiter
 * with the same interface replaces it when the API is scaled horizontally.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private lastSweep = Date.now();

  constructor(private readonly now: () => number = Date.now) {}

  /** Returns true when the request is allowed. */
  take(
    key: string,
    capacity: number,
    refillPerSecond: number,
  ): { allowed: boolean; retryAfterSeconds: number } {
    const t = this.now();
    this.sweep(t);
    const b = this.buckets.get(key) ?? { tokens: capacity, updatedAt: t };
    const elapsed = (t - b.updatedAt) / 1000;
    b.tokens = Math.min(capacity, b.tokens + elapsed * refillPerSecond);
    b.updatedAt = t;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      this.buckets.set(key, b);
      return { allowed: true, retryAfterSeconds: 0 };
    }
    this.buckets.set(key, b);
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((1 - b.tokens) / refillPerSecond)),
    };
  }

  reset(): void {
    this.buckets.clear();
  }

  private sweep(t: number): void {
    if (t - this.lastSweep < 60_000) return;
    this.lastSweep = t;
    for (const [k, b] of this.buckets) if (t - b.updatedAt > 300_000) this.buckets.delete(k);
  }
}

export function rateLimit(
  limiter: RateLimiter,
  opts: { name: string; capacity: number; refillPerSecond: number; keyBy?: 'ip' | 'ip+user' },
): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const ip = c.get('clientIp') ?? 'unknown';
    const user = opts.keyBy === 'ip+user' ? (c.get('principal')?.userId ?? '-') : '';
    const { allowed, retryAfterSeconds } = limiter.take(
      `${opts.name}:${ip}:${user}`,
      opts.capacity,
      opts.refillPerSecond,
    );
    if (!allowed) {
      c.get('log').warn({ bucket: opts.name, ip }, 'rate limited');
      throw new HTTPException(429, {
        res: new Response(
          JSON.stringify({
            error: {
              code: 'rate_limited',
              message: 'Too many requests',
              requestId: c.get('requestId'),
            },
          }),
          {
            status: 429,
            headers: {
              'content-type': 'application/json',
              'retry-after': String(retryAfterSeconds),
            },
          },
        ),
      });
    }
    await next();
  };
}
