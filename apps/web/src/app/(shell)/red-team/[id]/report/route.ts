import { API_BASE } from '@/lib/api';
import { getAccessToken } from '@/lib/session';

export const dynamic = 'force-dynamic';

/** BFF download of the engagement report as Markdown; authorization and content come from the API. */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return new Response('not found', { status: 404 });
  const token = await getAccessToken();
  if (!token) return new Response('unauthenticated', { status: 401 });
  const upstream = await fetch(
    `${API_BASE}/api/v1/assessments/engagements/${id}/report?format=markdown`,
    { headers: { accept: 'text/markdown', authorization: `Bearer ${token}` }, cache: 'no-store' },
  );
  if (!upstream.ok) return new Response('report unavailable', { status: upstream.status });
  const body = await upstream.text();
  const ref = /^# Assessment report — (.+)$/m.exec(body)?.[1]?.replace(/[^A-Za-z0-9_-]+/g, '-');
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/markdown; charset=utf-8',
      'content-disposition': `attachment; filename="engagement-${ref || id.slice(0, 8)}.md"`,
      'cache-control': 'no-store',
    },
  });
}
