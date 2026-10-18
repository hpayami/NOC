import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import pino from 'pino';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MiniRedis, RedisRateLimiter, parseRedisUrl } from '../src/middleware/redis-limiter';
import { RedisAlertBus } from '../src/events/redis-bus';

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

describe('shared alert bus', () => {
  it('fans alerts out across instances exactly once and drops malformed messages', async () => {
    const a = new RedisAlertBus(url, logger, 'test:alerts');
    const b = new RedisAlertBus(url, logger, 'test:alerts');
    await Promise.all([a.listen(), b.listen()]);
    const gotA: string[] = [];
    const gotB: string[] = [];
    const offA = a.subscribe((e) => gotA.push(e.alertId));
    const offB = b.subscribe((e) => gotB.push(e.alertId));
    expect(offA && offB).toBeTruthy();
    const ev = {
      kind: 'created' as const,
      alertId: '11111111-1111-4111-8111-111111111111',
      severity: 'high' as const,
      title: 'cross-instance',
      at: new Date().toISOString(),
    };
    a.publish(ev);
    for (let i = 0; i < 50 && gotB.length === 0; i++) await new Promise((r) => setTimeout(r, 50));
    expect(gotB).toEqual([ev.alertId]);
    // The publishing instance delivered locally once; the echo of its own message is ignored.
    await new Promise((r) => setTimeout(r, 150));
    expect(gotA).toEqual([ev.alertId]);
    expect(b.receivedCount).toBe(1);
    expect(a.receivedCount).toBe(0);
    // Garbage and contract-violating payloads on the channel are dropped, not fanned out.
    const raw = new MiniRedis(parseRedisUrl(url));
    await raw.command('PUBLISH', 'test:alerts', 'not json');
    await raw.command(
      'PUBLISH',
      'test:alerts',
      JSON.stringify({ origin: 'x', event: { kind: 'created', alertId: 'nope' } }),
    );
    await raw.command('PUBLISH', 'test:alerts', JSON.stringify({ origin: 'y', event: ev }));
    for (let i = 0; i < 50 && (gotB.length < 2 || gotA.length < 2); i++)
      await new Promise((r) => setTimeout(r, 50));
    expect(gotB).toEqual([ev.alertId, ev.alertId]);
    expect(gotA).toEqual([ev.alertId, ev.alertId]);
    raw.close();
    offA!();
    offB!();
    expect(a.subscribers).toBe(0);
    a.close();
    b.close();
  });

  it('serves local subscribers when redis is unreachable and reports degradation', async () => {
    const port = await freePort();
    const bus = new RedisAlertBus(`redis://127.0.0.1:${port}/0`, logger, 'test:alerts');
    const got: string[] = [];
    bus.subscribe((e) => got.push(e.alertId));
    bus.publish({
      kind: 'created',
      alertId: '22222222-2222-4222-8222-222222222222',
      severity: 'low',
      title: 'local only',
      at: new Date().toISOString(),
    });
    for (let i = 0; i < 40 && !bus.isDegraded; i++) await new Promise((r) => setTimeout(r, 50));
    expect(got).toHaveLength(1);
    expect(bus.isDegraded).toBe(true);
    bus.close();
  });
});
