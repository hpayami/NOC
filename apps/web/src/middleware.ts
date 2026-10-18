import { NextResponse, type NextRequest } from 'next/server';

const PUBLIC = ['/login', '/auth/refresh', '/auth/logout', '/_next', '/favicon.ico'];

/**
 * Edge gate: pages under the shell require a session cookie. This is a UX convenience only;
 * authorization is enforced by the API on every call with the Bearer token.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC.some((p) => pathname.startsWith(p))) return NextResponse.next();
  if (!req.cookies.get('noc_access')) {
    const url = req.nextUrl.clone();
    url.pathname = '/login';
    url.search = req.cookies.get('noc_refresh') ? '?reason=expired' : '';
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };
