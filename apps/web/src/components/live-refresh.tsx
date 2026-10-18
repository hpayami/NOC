'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

/** Subscribes to the alert stream and refreshes the server-rendered page when something changes. */
export function LiveRefresh({ labels }: { labels: { live: string; offline: string } }) {
  const router = useRouter();
  const [state, setState] = useState<'connecting' | 'live' | 'offline'>('connecting');
  useEffect(() => {
    const es = new EventSource('/stream/alerts');
    let timer: ReturnType<typeof setTimeout> | null = null;
    const schedule = () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        router.refresh();
      }, 1000);
    };
    es.addEventListener('ready', () => setState('live'));
    es.addEventListener('alert', schedule);
    es.onerror = () => setState('offline');
    return () => {
      if (timer) clearTimeout(timer);
      es.close();
    };
  }, [router]);
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs ${state === 'live' ? 'text-ok' : 'text-muted'}`}
      aria-live="polite"
    >
      <span
        className={`inline-block h-2 w-2 rounded-full ${state === 'live' ? 'bg-ok' : 'bg-border'}`}
      />
      {state === 'live' ? labels.live : labels.offline}
    </span>
  );
}
