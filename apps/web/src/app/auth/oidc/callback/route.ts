import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { TokenResponse } from '@noc/shared';
import { apiPublic } from '@/lib/api';
import { extractApiRefreshCookie, storeSession } from '@/lib/session';
import { OIDC_STATE_COOKIE } from '../start/route';

export const dynamic = 'force-dynamic';

/**
 * IdP redirect target. The state must match the cookie set at start (binds the login to this
 * browser); the code exchange and ID-token verification happen in the API, never here.
 */
export async function GET(req: Request) {
  const origin = process.env.WEB_ORIGIN ?? 'http://localhost:3000';
  const url = new URL(req.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const store = await cookies();
  const expected = store.get(OIDC_STATE_COOKIE)?.value;
  store.delete({ name: OIDC_STATE_COOKIE, path: '/auth/oidc' });
  if (!code || !state || !expected || state !== expected)
    return NextResponse.redirect(new URL('/login?reason=sso_state', origin));
  const res = await apiPublic('/api/v1/auth/oidc/callback', {
    method: 'POST',
    body: JSON.stringify({ code, state }),
  });
  if (res.status !== 200) {
    const reason =
      res.status === 409 ? 'sso_collision' : res.status === 403 ? 'sso_refused' : 'sso_failed';
    return NextResponse.redirect(new URL(`/login?reason=${reason}`, origin));
  }
  const body = TokenResponse.parse(await res.json());
  await storeSession(body, extractApiRefreshCookie(res.headers.get('set-cookie')));
  return NextResponse.redirect(new URL('/command-center', origin));
}
