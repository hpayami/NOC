'use client';

import { useActionState } from 'react';
import { issueEnrolmentToken, type EnrolmentState } from './actions';

export function EnrolmentTokenButton({
  sensorId,
  labels,
}: {
  sensorId: string;
  labels: Record<'issue' | 'shownOnce' | 'expires', string>;
}) {
  const [state, action, pending] = useActionState<EnrolmentState, FormData>(
    issueEnrolmentToken,
    null,
  );
  return (
    <form action={action} className="space-y-2">
      <input type="hidden" name="sensorId" value={sensorId} />
      <button
        type="submit"
        disabled={pending}
        className="rounded-md border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60"
      >
        {labels.issue}
      </button>
      {state && 'token' in state ? (
        <div className="rounded border border-sev-medium/40 bg-sev-medium/10 p-2 text-xs">
          <p className="text-sev-medium">{labels.shownOnce}</p>
          <code className="ltr mt-1 block select-all break-all">{state.token}</code>
          <p className="mt-1 text-muted">
            {labels.expires}: <span className="ltr">{state.expiresAt}</span>
          </p>
        </div>
      ) : state && 'error' in state ? (
        <p role="alert" className="text-xs text-sev-critical">
          {state.error}
        </p>
      ) : null}
    </form>
  );
}
