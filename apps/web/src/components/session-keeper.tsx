'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/** Rotates the session ~60 s before the access token expires; sends the user to login if refused. */
export function SessionKeeper({ expiresInSeconds }: { expiresInSeconds: number }) {
  const router = useRouter();
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const schedule = (secs: number) => {
      timer = setTimeout(
        async () => {
          try {
            const res = await fetch('/auth/refresh', {
              method: 'POST',
              credentials: 'same-origin',
            });
            if (cancelled) return;
            if (!res.ok) return router.replace('/login?reason=expired');
            const body = (await res.json()) as { expiresInSeconds: number };
            schedule(body.expiresInSeconds);
          } catch {
            if (!cancelled) schedule(30);
          }
        },
        Math.max(15, secs - 60) * 1000,
      );
    };
    schedule(expiresInSeconds);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [expiresInSeconds, router]);
  return null;
}
