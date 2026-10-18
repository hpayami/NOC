import { randomUUID } from 'node:crypto';
import type { Logger } from 'pino';
import { AlertStreamEvent } from '@noc/shared';
import { MiniRedis, parseRedisUrl } from '../middleware/redis-limiter';
import { AlertBus, type AlertBusLike } from './bus';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Alert bus for more than one API instance: local fan-out plus Redis pub/sub so an SSE client
 * connected to any instance sees alerts ingested on every instance. Semantics are at-most-once and
 * best effort — the stream is a nudge to re-fetch, never the record. Local subscribers are always
 * served even when Redis is down; the outage is logged once and the subscriber reconnects with
 * backoff. Messages from this instance are not re-delivered to it (origin id in the envelope).
 */
export class RedisAlertBus implements AlertBusLike {
  readonly instanceId = randomUUID();
  private readonly local: AlertBus;
  private readonly pub: MiniRedis;
  private readonly sub: MiniRedis;
  private stopped = false;
  private degraded = false;
  private retryMs = 500;
  private listening: Promise<void> | null = null;
  private received = 0;

  constructor(
    url: string,
    private readonly logger: Logger,
    private readonly channel = 'noc:alerts',
    maxListeners = 200,
  ) {
    this.local = new AlertBus(maxListeners);
    const opts = parseRedisUrl(url);
    this.pub = new MiniRedis(opts);
    this.sub = new MiniRedis({
      ...opts,
      onPush: (msg) => this.onMessage(msg),
      onClose: () => {
        if (!this.stopped) void this.listen();
      },
    });
    void this.listen();
  }

  /** Subscribes (re-subscribes after a drop) with exponential backoff; resolves once subscribed. */
  listen(): Promise<void> {
    if (this.listening) return this.listening;
    this.listening = (async () => {
      while (!this.stopped) {
        try {
          await this.sub.command('SUBSCRIBE', this.channel);
          if (this.degraded)
            this.logger.info('alert bus: redis recovered; cross-instance fan-out active');
          this.degraded = false;
          this.retryMs = 500;
          return;
        } catch (err) {
          if (!this.degraded)
            this.logger.error(
              { err: err instanceof Error ? err.message : String(err) },
              'alert bus: redis unavailable; serving this instance only',
            );
          this.degraded = true;
          await sleep(this.retryMs);
          this.retryMs = Math.min(this.retryMs * 2, 10_000);
        }
      }
    })().finally(() => (this.listening = null));
    return this.listening;
  }

  private onMessage(msg: unknown): void {
    if (!Array.isArray(msg) || msg[0] !== 'message' || msg[1] !== this.channel) return;
    let envelope: { origin?: unknown; event?: unknown };
    try {
      envelope = JSON.parse(String(msg[2]));
    } catch {
      return;
    }
    if (envelope.origin === this.instanceId) return;
    // Bus payloads are validated like any other input: a bad message is dropped, not fanned out.
    const parsed = AlertStreamEvent.safeParse(envelope.event);
    if (!parsed.success) return;
    this.received++;
    this.local.publish(parsed.data);
  }

  publish(event: AlertStreamEvent): void {
    this.local.publish(event);
    const payload = JSON.stringify({ origin: this.instanceId, event });
    this.pub.command('PUBLISH', this.channel, payload).catch((err: unknown) => {
      if (!this.degraded)
        this.logger.error(
          { err: err instanceof Error ? err.message : String(err) },
          'alert bus: publish failed; other instances will not see this event',
        );
      this.degraded = true;
    });
  }

  subscribe(listener: (event: AlertStreamEvent) => void): (() => void) | null {
    return this.local.subscribe(listener);
  }

  get subscribers(): number {
    return this.local.subscribers;
  }

  get isDegraded(): boolean {
    return this.degraded;
  }

  /** Cross-instance messages accepted so far (diagnostics/tests). */
  get receivedCount(): number {
    return this.received;
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.pub.command('PING')) === 'PONG';
    } catch {
      return false;
    }
  }

  close(): void {
    this.stopped = true;
    this.pub.close();
    this.sub.close();
  }
}
