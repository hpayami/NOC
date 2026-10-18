import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { TokenResponse } from '@noc/shared';
import { apiPublic } from '@/lib/api';
import { REFRESH_COOKIE, clearSession, extractApiRefreshCookie, storeSession } from '@/lib/session';

/**
 * Rotates the session before the access token expires. Called by the shell's session keeper with
 * same-origin credentials; the API additionally checks Origin and rotates the refresh family.
 */
export async function POST(req: Request) {
  const origin = req.headers.get('origin');
  const expected = process.env.WEB_ORIGIN ?? 'http://localhost:3000';
  if (origin && origin !== expected)
    return NextResponse.json({ error: 'bad_origin' }, { status: 403 });

  const refresh = (await cookies()).get(REFRESH_COOKIE)?.value;
  if (!refresh) return NextResponse.json({ error: 'no_session' }, { status: 401 });

  const res = await apiPublic('/api/v1/auth/refresh', {
    method: 'POST',
    headers: { cookie: `noc_refresh=${refresh}` },
  });
  if (res.status !== 200) {
    await clearSession();
    return NextResponse.json({ error: 'refresh_rejected' }, { status: 401 });
  }
  const body = TokenResponse.parse(await res.json());
  await storeSession(body, extractApiRefreshCookie(res.headers.get('set-cookie')));
  return NextResponse.json({ expiresInSeconds: body.expiresInSeconds });
}
