import type { Context, ErrorHandler, NotFoundHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';
import type { AppEnv } from './context';

export function errorBody(c: Context<AppEnv>, code: string, message: string, details?: unknown) {
  return {
    error: {
      code,
      message,
      requestId: c.get('requestId'),
      ...(details !== undefined ? { details } : {}),
    },
  };
}

export const notFound: NotFoundHandler<AppEnv> = (c) =>
  c.json(errorBody(c, 'not_found', 'Route not found'), 404);

export const onError: ErrorHandler<AppEnv> = (err, c) => {
  const log = c.get('log');
  if (err instanceof HTTPException) {
    if (err.res) return err.res;
    const code =
      err.status === 401
        ? 'unauthenticated'
        : err.status === 403
          ? 'forbidden'
          : err.status === 413
            ? 'payload_too_large'
            : 'http_error';
    return c.json(errorBody(c, code, err.message), err.status);
  }
  if (err instanceof ZodError) {
    return c.json(
      errorBody(
        c,
        'validation_failed',
        'Request failed validation',
        err.issues.map((i) => ({ path: i.path, message: i.message })),
      ),
      400,
    );
  }
  log?.error({ err }, 'unhandled error');
  return c.json(errorBody(c, 'internal_error', 'Internal server error'), 500);
};
