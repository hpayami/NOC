import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

export function createMetrics() {
  const registry = new Registry();
  collectDefaultMetrics({ register: registry, prefix: 'noc_api_' });

  const httpRequests = new Counter({
    name: 'noc_api_http_requests_total',
    help: 'HTTP requests by method, route and status',
    labelNames: ['method', 'route', 'status'] as const,
    registers: [registry],
  });
  const httpDuration = new Histogram({
    name: 'noc_api_http_request_duration_seconds',
    help: 'HTTP request latency',
    labelNames: ['method', 'route'] as const,
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    registers: [registry],
  });
  const authFailures = new Counter({
    name: 'noc_api_auth_failures_total',
    help: 'Failed authentication attempts by reason',
    labelNames: ['reason'] as const,
    registers: [registry],
  });
  const dbUp = new Gauge({
    name: 'noc_api_database_up',
    help: '1 when the database answers',
    registers: [registry],
  });

  return { registry, httpRequests, httpDuration, authFailures, dbUp };
}

export type Metrics = ReturnType<typeof createMetrics>;
