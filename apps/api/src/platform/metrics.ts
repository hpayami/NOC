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

  const eventsIngested = new Counter({
    name: 'noc_api_events_ingested_total',
    help: 'Normalized events accepted by sensor and product',
    labelNames: ['sensor', 'product'] as const,
    registers: [registry],
  });
  const eventsDuplicate = new Counter({
    name: 'noc_api_events_duplicate_total',
    help: 'Events dropped as exact duplicates',
    registers: [registry],
  });
  const eventsRejected = new Counter({
    name: 'noc_api_events_rejected_total',
    help: 'Records rejected during normalization by reason',
    labelNames: ['reason'] as const,
    registers: [registry],
  });
  const alertsCreated = new Counter({
    name: 'noc_api_alerts_created_total',
    help: 'Alerts opened by severity',
    labelNames: ['severity'] as const,
    registers: [registry],
  });
  const ingestLag = new Gauge({
    name: 'noc_api_ingest_lag_seconds',
    help: 'Seconds between the newest accepted event time and ingestion, per sensor',
    labelNames: ['sensor'] as const,
    registers: [registry],
  });

  return {
    registry,
    httpRequests,
    httpDuration,
    authFailures,
    dbUp,
    eventsIngested,
    eventsDuplicate,
    eventsRejected,
    alertsCreated,
    ingestLag,
  };
}

export type Metrics = ReturnType<typeof createMetrics>;
