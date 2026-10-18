import { OpenAPIHono } from '@hono/zod-openapi';
import { bodyLimit } from 'hono/body-limit';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { HTTPException } from 'hono/http-exception';
import type { Deps } from './app-deps';
import { authenticate, authenticateSensor } from './middleware/auth';
import { requestContext, type AppEnv } from './middleware/context';
import { errorBody, notFound, onError } from './middleware/errors';
import { rateLimit } from './middleware/rate-limit';
import { agentRoutes } from './routes/agents';
import { alertRoutes, eventRoutes } from './routes/alerts';
import { incidentRoutes } from './routes/incidents';
import { ipsRoutes } from './routes/ips';
import { ingestRoutes } from './routes/ingest';
import { responseRoutes } from './routes/response';
import { retentionRoutes } from './routes/retention';
import { ruleRoutes } from './routes/rules';
import { assetRoutes } from './routes/assets';
import { authRoutes } from './routes/auth';
import { collectorRoutes } from './routes/collectors';
import { discoveryRoutes } from './routes/discovery';
import { assetMetricRoutes, monitoringRoutes } from './routes/monitoring';
import { networkRoutes } from './routes/network';
import { sensorRoutes } from './routes/sensors';
import { auditRoutes, healthRoutes, platformRoutes } from './routes/platform';
import { roleRoutes, userRoutes } from './routes/users';

export function createApp(deps: Deps) {
  const { env, db, tokens, logger, limiter, metrics } = deps;

  const app = new OpenAPIHono<AppEnv>({
    // Zod validation failures become structured 400s instead of leaking internals.
    defaultHook: (result, c) => {
      if (!result.success) {
        return c.json(
          errorBody(
            c,
            'validation_failed',
            'Request failed validation',
            result.error.issues.map((i) => ({ path: i.path, message: i.message })),
          ),
          400,
        );
      }
      return undefined;
    },
  });

  app.onError(onError);
  app.notFound(notFound);

  app.use('*', requestContext(env, logger));
  app.use(
    '*',
    secureHeaders({ crossOriginResourcePolicy: 'same-origin', referrerPolicy: 'no-referrer' }),
  );
  app.use(
    '*',
    cors({
      origin: (origin) => (env.CORS_ALLOWED_ORIGINS.includes(origin) ? origin : null),
      credentials: true,
      allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowHeaders: ['Authorization', 'Content-Type', 'X-Request-Id'],
      exposeHeaders: ['X-Request-Id', 'Retry-After'],
      maxAge: 600,
    }),
  );
  const limitFor = (max: number) =>
    bodyLimit({
      maxSize: max,
      onError: () => {
        throw new HTTPException(413, { message: 'Request body too large' });
      },
    });
  app.use('/api/v1/ingest/*', limitFor(env.INGEST_BODY_LIMIT_BYTES));
  app.use('/api/v1/detection-rules/import', limitFor(env.INGEST_BODY_LIMIT_BYTES));
  app.use('*', async (c, next) =>
    c.req.path.startsWith('/api/v1/ingest/') || c.req.path === '/api/v1/detection-rules/import'
      ? next()
      : limitFor(env.BODY_LIMIT_BYTES)(c, next),
  );
  app.use('*', async (c, next) => {
    const end = metrics.httpDuration.startTimer({ method: c.req.method, route: c.req.routePath });
    await next();
    end();
    metrics.httpRequests.inc({
      method: c.req.method,
      route: c.req.routePath,
      status: String(c.res.status),
    });
  });
  app.use('*', authenticate(db, tokens));
  app.use('/api/v1/agents/*', authenticateSensor(db));
  app.use('/api/v1/ingest/*', authenticateSensor(db));
  app.use(
    '/api/*',
    rateLimit(limiter, { name: 'api', capacity: 300, refillPerSecond: 5, keyBy: 'ip+user' }),
  );

  app.route('/', healthRoutes(deps));
  app.route('/api/v1/auth', authRoutes(deps));
  app.route('/api/v1/users', userRoutes(deps));
  app.route('/api/v1/roles', roleRoutes());
  app.route('/api/v1/assets', assetRoutes(deps));
  app.route('/api/v1/assets', assetMetricRoutes(deps));
  app.route('/api/v1/network', networkRoutes(deps));
  app.route('/api/v1/monitoring', monitoringRoutes(deps));
  app.route('/api/v1/sensors', sensorRoutes(deps));
  app.route('/api/v1/discovery', discoveryRoutes(deps).app);
  app.route('/api/v1/collectors', collectorRoutes(deps));
  app.route('/api/v1/agents', agentRoutes(deps).app);
  app.route('/api/v1/ingest', ingestRoutes(deps));
  app.route('/api/v1/alerts', alertRoutes(deps));
  app.route('/api/v1/events', eventRoutes(deps));
  app.route('/api/v1/detection-rules', ruleRoutes(deps));
  app.route('/api/v1/incidents', incidentRoutes(deps));
  app.route('/api/v1/response-actions', responseRoutes(deps));
  app.route('/api/v1/ips', ipsRoutes(deps, deps.ips));
  app.route('/api/v1/retention', retentionRoutes(deps, deps.retention));
  app.route('/api/v1/platform', platformRoutes(deps));
  app.route('/api/v1/audit', auditRoutes(deps));

  app.openAPIRegistry.registerComponent('securitySchemes', 'sensorCredential', {
    type: 'apiKey',
    in: 'header',
    name: 'X-Sensor-Credential',
  });
  app.openAPIRegistry.registerComponent('securitySchemes', 'bearerAuth', {
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
  });
  app.doc31('/api/v1/openapi.json', {
    openapi: '3.1.0',
    info: {
      title: 'NOC Platform API',
      version: env.APP_VERSION,
      description:
        'Phase 0 management-plane API. Capabilities not listed as "available" in /api/v1/platform/status are not operational.',
    },
    servers: [{ url: '/' }],
  });

  return app;
}

export type App = ReturnType<typeof createApp>;
