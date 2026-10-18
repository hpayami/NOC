'use client';

import { useActionState } from 'react';
import { verifyChainAction, type VerifyState } from './actions';

export function VerifyChainButton({
  labels,
}: {
  labels: Record<'verify' | 'valid' | 'invalid' | 'checked', string>;
}) {
  const [state, action, pending] = useActionState<VerifyState, FormData>(verifyChainAction, null);
  return (
    <form action={action} className="flex items-center gap-3">
      <button
        type="submit"
        disabled={pending}
        className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm hover:bg-surface-2 disabled:opacity-60"
      >
        {labels.verify}
      </button>
      {state ? (
        <span className={`text-sm ${state.valid ? 'text-ok' : 'text-sev-critical'}`} role="status">
          {state.valid ? labels.valid : `${labels.invalid} (seq ${state.firstBrokenSeq})`} ·{' '}
          {state.eventsChecked} {labels.checked}
        </span>
      ) : null}
    </form>
  );
}
