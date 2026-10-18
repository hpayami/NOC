import { EventEmitter } from 'node:events';
import type { AlertStreamEvent } from '@noc/shared';

/** What the SSE route and the publishers depend on; `AlertBus` (in-process) and `RedisAlertBus` implement it. */
export interface AlertBusLike {
  publish(event: AlertStreamEvent): void;
  subscribe(listener: (event: AlertStreamEvent) => void): (() => void) | null;
  readonly subscribers: number;
}

/**
 * In-process fan-out for live UI updates. Single-instance by design; `RedisAlertBus` wraps it for
 * multi-instance deployments. Listeners are capped so a stuck client cannot grow memory unbounded.
 */
export class AlertBus implements AlertBusLike {
  private readonly emitter = new EventEmitter();
  readonly maxListeners: number;

  constructor(maxListeners = 200) {
    this.maxListeners = maxListeners;
    this.emitter.setMaxListeners(maxListeners + 1);
  }

  publish(event: AlertStreamEvent): void {
    this.emitter.emit('alert', event);
  }

  /** Returns an unsubscribe function, or null when the listener cap is reached. */
  subscribe(listener: (event: AlertStreamEvent) => void): (() => void) | null {
    if (this.emitter.listenerCount('alert') >= this.maxListeners) return null;
    this.emitter.on('alert', listener);
    return () => this.emitter.off('alert', listener);
  }

  get subscribers(): number {
    return this.emitter.listenerCount('alert');
  }
}
