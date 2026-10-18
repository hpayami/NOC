'use client';

import { useActionState, useRef } from 'react';
import type { AlertStatus } from '@noc/shared';
import { triageAlert, type TriageState } from './actions';

const QUICK: Record<
  AlertStatus,
  Array<'acknowledge' | 'investigate' | 'resolve' | 'false_positive' | 'reopen'>
> = {
  new: ['acknowledge', 'investigate', 'false_positive'],
  acknowledged: ['investigate', 'resolve', 'false_positive'],
  investigating: ['resolve', 'false_positive'],
  escalated: ['investigate', 'resolve'],
  suppressed: ['reopen', 'resolve'],
  false_positive: ['reopen'],
  resolved: ['reopen'],
};
const NEEDS_NOTE = new Set(['resolve', 'false_positive', 'reopen']);

export function TriageButtons({
  alertId,
  status,
  labels,
}: {
  alertId: string;
  status: AlertStatus;
  labels: Record<
    'acknowledge' | 'investigate' | 'resolve' | 'false_positive' | 'reopen' | 'note',
    string
  >;
}) {
  const [state, action, pending] = useActionState<TriageState, FormData>(triageAlert, null);
  const actionRef = useRef<HTMLInputElement>(null);
  const actions = QUICK[status];
  const needsNote = actions.some((a) => NEEDS_NOTE.has(a));
  return (
    <form action={action} className="flex flex-wrap items-center gap-1">
      <input type="hidden" name="alertId" value={alertId} />
      <input type="hidden" name="action" ref={actionRef} />
      {needsNote ? (
        <input
          name="note"
          placeholder={labels.note}
          className="w-40 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
        />
      ) : null}
      {actions.map((a) => (
        <button
          key={a}
          type="submit"
          onClick={() => {
            if (actionRef.current) actionRef.current.value = a;
          }}
          disabled={pending}
          className="rounded border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60"
        >
          {labels[a]}
        </button>
      ))}
      {state?.error ? (
        <span role="alert" className="text-xs text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}
