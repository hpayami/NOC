import { API_BASE } from '@/lib/api';
import { getAccessToken } from '@/lib/session';

export const dynamic = 'force-dynamic';

/**
 * BFF proxy for the alert SSE stream: EventSource cannot send Authorization headers, so the
 * browser connects here with its session cookie and this handler forwards the Bearer token.
 */
export async function GET(req: Request) {
  const token = await getAccessToken();
  if (!token) return new Response('unauthenticated', { status: 401 });
  const upstream = await fetch(`${API_BASE}/api/v1/alerts/stream`, {
    headers: { accept: 'text/event-stream', authorization: `Bearer ${token}` },
    signal: req.signal,
    cache: 'no-store',
  });
  if (!upstream.ok || !upstream.body)
    return new Response('stream unavailable', { status: upstream.status === 403 ? 403 : 502 });
  return new Response(upstream.body, {
    status: 200,
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    },
  });
}
