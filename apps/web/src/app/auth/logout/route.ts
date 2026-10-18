import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { LogoutResponse } from '@noc/shared';
import { apiPublic } from '@/lib/api';
import { REFRESH_COOKIE, clearSession } from '@/lib/session';

/**
 * Ends the local session, then — for SSO accounts when the deployment registered a post-logout
 * URI — sends the browser to the IdP's end-session endpoint (RP-initiated logout) so the IdP
 * session ends too; otherwise back to the login page.
 */
export async function POST(req: Request) {
  const refresh = (await cookies()).get(REFRESH_COOKIE)?.value;
  let next = new URL('/login', req.url);
  if (refresh) {
    try {
      const res = await apiPublic('/api/v1/auth/logout', {
        method: 'POST',
        headers: { cookie: `noc_refresh=${refresh}` },
      });
      if (res.ok) {
        const body = LogoutResponse.safeParse(await res.json());
        if (body.success && body.data.idpLogoutUrl) next = new URL(body.data.idpLogoutUrl);
      }
    } catch {
      /* API unreachable: the local session is cleared regardless */
    }
  }
  await clearSession();
  return NextResponse.redirect(next, { status: 303 });
}
