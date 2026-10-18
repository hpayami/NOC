import 'server-only';
import { redirect } from 'next/navigation';
import type { z } from 'zod';
import { getAccessToken } from './session';

export const API_BASE = process.env.API_INTERNAL_URL ?? 'http://127.0.0.1:4000';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Server-side call to the API with the session's Bearer token. 401 → back to login. */
export async function apiFetch<T>(
  path: string,
  schema: z.ZodType<T>,
  init: RequestInit & { allowForbidden?: boolean } = {},
): Promise<T> {
  const token = await getAccessToken();
  if (!token) redirect('/login?reason=expired');
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
    cache: 'no-store',
  });
  if (res.status === 401) redirect('/login?reason=expired');
  // Server-side authorization is final; surface it as a page instead of a crashed render.
  if (res.status === 403 && (init.method ?? 'GET') === 'GET' && !init.allowForbidden)
    redirect(`/forbidden?from=${encodeURIComponent(path)}`);
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as {
      error?: { code?: string; message?: string };
    } | null;
    throw new ApiError(
      res.status,
      body?.error?.code ?? 'http_error',
      body?.error?.message ?? res.statusText,
    );
  }
  return schema.parse(await res.json());
}

/** Unauthenticated call (login, health). */
export async function apiPublic(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      origin: process.env.WEB_ORIGIN ?? 'http://localhost:3000',
      ...(init.headers ?? {}),
    },
    cache: 'no-store',
  });
}
