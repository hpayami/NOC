'use client';

import { useActionState } from 'react';
import { IncidentTypeValues, SeverityValues } from '@noc/shared';
import { createIncident, type ActionState } from './actions';

export function NewIncidentForm({
  labels,
}: {
  labels: Record<'heading' | 'title' | 'type' | 'severity' | 'summary' | 'submit', string> & {
    types: Record<(typeof IncidentTypeValues)[number], string>;
  };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createIncident, null);
  const input = 'w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form
      action={action}
      className="grid gap-3 rounded-lg border border-border bg-surface p-5 md:grid-cols-3"
    >
      <h2 className="font-medium md:col-span-3">{labels.heading}</h2>
      <label className="space-y-1 text-sm md:col-span-3">
        <span className="text-muted">{labels.title}</span>
        <input name="title" required maxLength={256} className={input} />
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.type}</span>
        <select name="type" className={input} defaultValue="security">
          {IncidentTypeValues.map((v) => (
            <option key={v} value={v}>
              {labels.types[v]}
            </option>
          ))}
        </select>
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.severity}</span>
        <select name="severity" className={`ltr ${input}`} defaultValue="medium">
          {SeverityValues.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </label>
      <label className="space-y-1 text-sm md:col-span-3">
        <span className="text-muted">{labels.summary}</span>
        <textarea name="summary" rows={3} maxLength={8192} className={input} />
      </label>
      <div className="flex items-center gap-3 md:col-span-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
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
