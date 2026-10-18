import { API_BASE } from '@/lib/api';
import { getAccessToken } from '@/lib/session';

export const dynamic = 'force-dynamic';

/** BFF proxy: the browser asks here with its session cookie; the API decides scope and content. */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return new Response('{"error":"bad id"}', { status: 400 });
  const token = await getAccessToken();
  if (!token) return new Response('{"error":"unauthenticated"}', { status: 401 });
  const upstream = await fetch(`${API_BASE}/api/v1/assets/${id}/risk`, {
    headers: { accept: 'application/json', authorization: `Bearer ${token}` },
    cache: 'no-store',
  });
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}
