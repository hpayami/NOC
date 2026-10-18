import 'server-only';
import { cookies } from 'next/headers';
import { SessionUser, type TokenResponse } from '@noc/shared';

export const ACCESS_COOKIE = 'noc_access';
export const REFRESH_COOKIE = 'noc_refresh';
export const USER_COOKIE = 'noc_user';

const secure = process.env.NODE_ENV === 'production';

/**
 * BFF session: the browser never sees API tokens. The access token and the API's refresh token are
 * held in httpOnly cookies scoped to this origin; server components forward the access token as a
 * Bearer header. The refresh cookie is restricted to the /auth path so ordinary pages never carry it.
 */
export async function storeSession(res: TokenResponse, apiRefreshCookie: string | null) {
  const store = await cookies();
  store.set(ACCESS_COOKIE, res.accessToken, {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
    maxAge: res.expiresInSeconds,
  });
  if (apiRefreshCookie) {
    store.set(REFRESH_COOKIE, apiRefreshCookie, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      path: '/auth',
    });
  }
  // Non-sensitive display info so the shell can render without a round-trip; authorization never reads it.
  store.set(USER_COOKIE, JSON.stringify(SessionUser.parse(res.user)), {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
  });
}

export async function clearSession() {
  const store = await cookies();
  store.delete(ACCESS_COOKIE);
  store.delete({ name: REFRESH_COOKIE, path: '/auth' });
  store.delete(USER_COOKIE);
}

export async function getAccessToken(): Promise<string | null> {
  return (await cookies()).get(ACCESS_COOKIE)?.value ?? null;
}

export async function getSessionUser(): Promise<SessionUser | null> {
  const raw = (await cookies()).get(USER_COOKIE)?.value;
  if (!raw) return null;
  const parsed = SessionUser.safeParse(JSON.parse(raw));
  return parsed.success ? parsed.data : null;
}

/** Extracts the API's refresh cookie value from a Set-Cookie header. */
export function extractApiRefreshCookie(setCookie: string | null): string | null {
  if (!setCookie) return null;
  return /noc_refresh=([^;]+)/.exec(setCookie)?.[1] ?? null;
}
