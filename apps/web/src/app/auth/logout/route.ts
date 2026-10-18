import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { apiPublic } from '@/lib/api';
import { REFRESH_COOKIE, clearSession } from '@/lib/session';

export async function POST(req: Request) {
  const refresh = (await cookies()).get(REFRESH_COOKIE)?.value;
  if (refresh)
    await apiPublic('/api/v1/auth/logout', {
      method: 'POST',
      headers: { cookie: `noc_refresh=${refresh}` },
    }).catch(() => undefined);
  await clearSession();
  return NextResponse.redirect(new URL('/login', req.url), { status: 303 });
}
