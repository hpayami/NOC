'use client';

import { useActionState, useRef } from 'react';
import type { IncidentStatus } from '@noc/shared';
import { addIncidentNote, transitionIncident, type ActionState } from '../actions';

export function TransitionControls({
  id,
  allowedNext,
  canClose,
  labels,
}: {
  id: string;
  allowedNext: IncidentStatus[];
  canClose: boolean;
  labels: { heading: string; reason: string; states: Record<IncidentStatus, string> };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(transitionIncident, null);
  const toRef = useRef<HTMLInputElement>(null);
  const targets = allowedNext.filter((s) => s !== 'closed' || canClose);
  if (targets.length === 0) return null;
  return (
    <form action={action} className="space-y-2 rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-medium">{labels.heading}</h2>
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="to" ref={toRef} />
      <input
        name="reason"
        placeholder={labels.reason}
        className="w-full rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      />
      <div className="flex flex-wrap gap-1">
        {targets.map((to) => (
          <button
            key={to}
            type="submit"
            onClick={() => {
              if (toRef.current) toRef.current.value = to;
            }}
            disabled={pending}
            className="rounded border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60"
          >
            → {labels.states[to]}
          </button>
        ))}
      </div>
      {state?.error ? (
        <p role="alert" className="text-xs text-sev-critical">
          {state.error}
        </p>
      ) : null}
    </form>
  );
}

export function NoteForm({ id, labels }: { id: string; labels: { note: string; submit: string } }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(addIncidentNote, null);
  return (
    <form action={action} className="space-y-2 rounded-lg border border-border bg-surface p-4">
      <input type="hidden" name="id" value={id} />
      <textarea
        name="note"
        required
        rows={3}
        maxLength={8192}
        placeholder={labels.note}
        className="w-full rounded border border-border bg-surface-2 px-2 py-1 text-sm"
      />
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2 disabled:opacity-60"
        >
          {labels.submit}
        </button>
        {state?.error ? (
          <span role="alert" className="text-xs text-sev-critical">
            {state.error}
          </span>
        ) : null}
      </div>
    </form>
  );
}
