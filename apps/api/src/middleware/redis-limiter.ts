import net from 'node:net';
import type { Logger } from 'pino';
import { RateLimiter } from './rate-limit';

export interface TakeResult {
  allowed: boolean;
  retryAfterSeconds: number;
}
export interface Limiter {
  take(key: string, capacity: number, refillPerSecond: number): TakeResult | Promise<TakeResult>;
  reset(): void | Promise<void>;
}

/**
 * Minimal RESP2 client: one socket, pipelined commands, no dependency. Enough for EVAL/EVALSHA,
 * PING, FLUSHDB and AUTH; reconnects lazily on the next command after an error.
 */
export class MiniRedis {
  private socket: net.Socket | null = null;
  private buf = Buffer.alloc(0);
  private readonly queue: Array<{ resolve: (v: unknown) => void; reject: (e: Error) => void }> = [];
  private connecting: Promise<void> | null = null;

  constructor(
    private readonly opts: {
      host: string;
      port: number;
      password?: string;
      db?: number;
      timeoutMs?: number;
    },
  ) {}

  private connect(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return Promise.resolve();
    if (this.connecting) return this.connecting;
    this.connecting = new Promise<void>((resolve, reject) => {
      const s = net.createConnection({ host: this.opts.host, port: this.opts.port });
      const timer = setTimeout(
        () => s.destroy(new Error('redis connect timeout')),
        this.opts.timeoutMs ?? 2000,
      );
      s.once('connect', async () => {
        clearTimeout(timer);
        this.socket = s;
        this.buf = Buffer.alloc(0);
        try {
          if (this.opts.password) await this.command('AUTH', this.opts.password);
          if (this.opts.db) await this.command('SELECT', String(this.opts.db));
          resolve();
        } catch (e) {
          reject(e as Error);
        }
      });
      s.on('data', (d) => this.onData(d));
      s.on('error', (err) => {
        clearTimeout(timer);
        this.fail(err);
        reject(err);
      });
      s.on('close', () => this.fail(new Error('redis connection closed')));
    }).finally(() => (this.connecting = null));
    return this.connecting;
  }

  private fail(err: Error): void {
    this.socket = null;
    const pending = this.queue.splice(0);
    for (const p of pending) p.reject(err);
  }

  private onData(d: Buffer): void {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      const r = this.parse(0);
      if (!r) return;
      this.buf = this.buf.subarray(r.next);
      const p = this.queue.shift();
      if (!p) continue;
      if (r.value instanceof Error) p.reject(r.value);
      else p.resolve(r.value);
    }
  }

  private parse(at: number): { value: unknown; next: number } | null {
    if (at >= this.buf.length) return null;
    const type = String.fromCharCode(this.buf[at]!);
    const eol = this.buf.indexOf('\r\n', at);
    if (eol < 0) return null;
    const line = this.buf.toString('utf8', at + 1, eol);
    const after = eol + 2;
    switch (type) {
      case '+':
        return { value: line, next: after };
      case '-':
        return { value: new Error(line), next: after };
      case ':':
        return { value: Number(line), next: after };
      case '$': {
        const len = Number(line);
        if (len < 0) return { value: null, next: after };
        if (this.buf.length < after + len + 2) return null;
        return { value: this.buf.toString('utf8', after, after + len), next: after + len + 2 };
      }
      case '*': {
        const n = Number(line);
        if (n < 0) return { value: null, next: after };
        const items: unknown[] = [];
        let cur = after;
        for (let i = 0; i < n; i++) {
          const item = this.parse(cur);
          if (!item) return null;
          items.push(item.value);
          cur = item.next;
        }
        return { value: items, next: cur };
      }
      default:
        return { value: new Error(`unexpected RESP type ${type}`), next: after };
    }
  }

  async command(...args: string[]): Promise<unknown> {
    await this.connect();
    const s = this.socket;
    if (!s) throw new Error('redis not connected');
    const payload = `*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join('')}`;
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      s.write(payload, (err) => err && reject(err));
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }
}

export function parseRedisUrl(url: string): {
  host: string;
  port: number;
  password?: string;
  db?: number;
} {
  const u = new URL(url);
  if (u.protocol !== 'redis:') throw new Error('REDIS_URL must use the redis:// scheme');
  const db = u.pathname && u.pathname !== '/' ? Number(u.pathname.slice(1)) : undefined;
  return {
    host: u.hostname || '127.0.0.1',
    port: Number(u.port || 6379),
    password: u.password ? decodeURIComponent(u.password) : undefined,
    db,
  };
}

/** Token bucket in Redis (atomic via Lua). KEYS[1]=bucket, ARGV: capacity, refill/s, now_ms, ttl_ms. */
const TOKEN_BUCKET_LUA = `
local b = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local tokens = tonumber(b[1])
local updated = tonumber(b[2])
if tokens == nil then tokens = capacity; updated = now end
local elapsed = math.max(0, now - updated) / 1000
tokens = math.min(capacity, tokens + elapsed * refill)
local allowed = 0
local retry = 0
if tokens >= 1 then tokens = tokens - 1; allowed = 1 else retry = math.max(1, math.ceil((1 - tokens) / refill)) end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', now)
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
return {allowed, retry}
`;

/**
 * Shared limiter for multi-instance deployments. On any Redis failure it degrades to the
 * in-process limiter (per instance, still protective) and logs once per outage; it never
 * fails open silently and never blocks all traffic because the cache is down.
 */
export class RedisRateLimiter implements Limiter {
  private readonly redis: MiniRedis;
  private readonly fallback = new RateLimiter();
  private degraded = false;
  private sha: string | null = null;

  constructor(
    url: string,
    private readonly logger: Logger,
    private readonly keyPrefix = 'noc:rl:',
  ) {
    this.redis = new MiniRedis(parseRedisUrl(url));
  }

  get isDegraded(): boolean {
    return this.degraded;
  }

  async take(key: string, capacity: number, refillPerSecond: number): Promise<TakeResult> {
    const now = Date.now();
    const ttlMs = Math.ceil((capacity / Math.max(refillPerSecond, 0.001)) * 1000) + 60_000;
    try {
      if (!this.sha)
        this.sha = String(await this.redis.command('SCRIPT', 'LOAD', TOKEN_BUCKET_LUA));
      let out: unknown;
      try {
        out = await this.redis.command(
          'EVALSHA',
          this.sha,
          '1',
          this.keyPrefix + key,
          String(capacity),
          String(refillPerSecond),
          String(now),
          String(ttlMs),
        );
      } catch (err) {
        if (!(err instanceof Error && err.message.startsWith('NOSCRIPT'))) throw err;
        this.sha = String(await this.redis.command('SCRIPT', 'LOAD', TOKEN_BUCKET_LUA));
        out = await this.redis.command(
          'EVALSHA',
          this.sha,
          '1',
          this.keyPrefix + key,
          String(capacity),
          String(refillPerSecond),
          String(now),
          String(ttlMs),
        );
      }
      const [allowed, retry] = out as [number, number];
      if (this.degraded) {
        this.degraded = false;
        this.logger.info('rate limiter: redis recovered; shared limits active again');
      }
      return { allowed: allowed === 1, retryAfterSeconds: Number(retry) };
    } catch (err) {
      if (!this.degraded) {
        this.degraded = true;
        this.logger.error(
          { err: err instanceof Error ? err.message : String(err) },
          'rate limiter: redis unavailable; falling back to per-instance limits',
        );
      }
      return this.fallback.take(key, capacity, refillPerSecond);
    }
  }

  async reset(): Promise<void> {
    this.fallback.reset();
    try {
      await this.redis.command('FLUSHDB');
    } catch {
      /* unreachable redis: nothing to flush */
    }
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.redis.command('PING')) === 'PONG';
    } catch {
      return false;
    }
  }

  close(): void {
    this.redis.close();
  }
}
