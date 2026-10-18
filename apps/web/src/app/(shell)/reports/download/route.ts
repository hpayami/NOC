import { API_BASE } from '@/lib/api';
import { getAccessToken } from '@/lib/session';

export const dynamic = 'force-dynamic';

/** BFF download of the posture report as Markdown; authorization and content come from the API. */
export async function GET(req: Request) {
  const days = Number(new URL(req.url).searchParams.get('days') ?? '30');
  if (!Number.isInteger(days) || days < 1 || days > 365)
    return new Response('bad request', { status: 400 });
  const token = await getAccessToken();
  if (!token) return new Response('unauthenticated', { status: 401 });
  const upstream = await fetch(`${API_BASE}/api/v1/reports/posture?days=${days}&format=markdown`, {
    headers: { accept: 'text/markdown', authorization: `Bearer ${token}` },
    cache: 'no-store',
  });
  if (!upstream.ok) return new Response('report unavailable', { status: upstream.status });
  const body = await upstream.text();
  const stamp = new Date().toISOString().slice(0, 10);
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/markdown; charset=utf-8',
      'content-disposition': `attachment; filename="posture-${days}d-${stamp}.md"`,
      'cache-control': 'no-store',
    },
  });
}
