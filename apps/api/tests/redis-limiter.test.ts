import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import pino from 'pino';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RedisRateLimiter, parseRedisUrl } from '../src/middleware/redis-limiter';

const freePort = () =>
  new Promise<number>((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });

let redis: ChildProcess | null = null;
let url = '';
const logger = pino({ level: 'silent' });

beforeAll(async () => {
  const port = await freePort();
  redis = spawn(
    'redis-server',
    [
      '--port',
      String(port),
      '--save',
      '',
      '--appendonly',
      'no',
      '--bind',
      '127.0.0.1',
      '--loglevel',
      'warning',
    ],
    { stdio: 'ignore' },
  );
  url = `redis://127.0.0.1:${port}/0`;
  const probe = new RedisRateLimiter(url, logger);
  for (let i = 0; i < 50 && !(await probe.ping()); i++)
    await new Promise((r) => setTimeout(r, 100));
  expect(await probe.ping()).toBe(true);
  probe.close();
});
afterAll(() => {
  redis?.kill('SIGTERM');
});

describe('shared rate limiter', () => {
  it('parses URLs and shares one bucket across API instances', async () => {
    expect(parseRedisUrl('redis://:s3cret@cache.internal:6380/2')).toEqual({
      host: 'cache.internal',
      port: 6380,
      password: 's3cret',
      db: 2,
    });
    expect(() => parseRedisUrl('http://x')).toThrow(/redis:/);
    const a = new RedisRateLimiter(url, logger, 'test:');
    const b = new RedisRateLimiter(url, logger, 'test:');
    await a.reset();
    // capacity 3: two instances draw from the same bucket.
    expect((await a.take('login:1.2.3.4', 3, 0.1)).allowed).toBe(true);
    expect((await b.take('login:1.2.3.4', 3, 0.1)).allowed).toBe(true);
    expect((await a.take('login:1.2.3.4', 3, 0.1)).allowed).toBe(true);
    const denied = await b.take('login:1.2.3.4', 3, 0.1);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect((await a.take('login:9.9.9.9', 3, 0.1)).allowed).toBe(true); // other key unaffected
    expect(a.isDegraded).toBe(false);
    a.close();
    b.close();
  });

  it('degrades to per-instance limits when redis is unreachable, and still limits', async () => {
    const dead = new RedisRateLimiter('redis://127.0.0.1:1/0', logger, 'test:');
    const results = [];
    for (let i = 0; i < 4; i++) results.push((await dead.take('k', 3, 0.1)).allowed);
    expect(results).toEqual([true, true, true, false]);
    expect(dead.isDegraded).toBe(true);
    dead.close();
  });
});
