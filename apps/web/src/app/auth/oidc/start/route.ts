import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { OidcStartResponse } from '@noc/shared';
import { apiPublic } from '@/lib/api';

export const OIDC_STATE_COOKIE = 'noc_oidc_state';
export const dynamic = 'force-dynamic';

/** Begins SSO: the API creates the PKCE state server-side; the browser only carries the opaque state. */
export async function GET() {
  const res = await apiPublic('/api/v1/auth/oidc/start', { method: 'POST' });
  if (res.status !== 200)
    return NextResponse.redirect(
      new URL('/login?reason=sso_unavailable', process.env.WEB_ORIGIN ?? 'http://localhost:3000'),
    );
  const body = OidcStartResponse.parse(await res.json());
  (await cookies()).set(OIDC_STATE_COOKIE, body.state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', // the IdP redirects back cross-site; 'strict' would drop the cookie
    path: '/auth/oidc',
    maxAge: body.expiresInSeconds,
  });
  return NextResponse.redirect(body.authorizationUrl);
}
