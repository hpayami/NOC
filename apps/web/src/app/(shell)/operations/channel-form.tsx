'use client';

import { useActionState } from 'react';
import { ConditionSeverityValues } from '@noc/shared';
import { createChannel, type CreateChannelState } from './actions';

export function CreateChannelForm({
  labels,
}: {
  labels: Record<
    'heading' | 'hint' | 'name' | 'url' | 'secret' | 'minSeverity' | 'submit' | 'created',
    string
  > & { severity: Record<(typeof ConditionSeverityValues)[number], string> };
}) {
  const [state, action, pending] = useActionState<CreateChannelState, FormData>(
    createChannel,
    null,
  );
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form action={action} className="space-y-3 rounded-lg border border-border bg-surface p-4">
      <h3 className="font-medium">{labels.heading}</h3>
      <p className="text-xs text-muted">{labels.hint}</p>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.name}</span>
          <input name="name" required maxLength={200} className={input} />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.url}</span>
          <input
            name="url"
            type="url"
            required
            placeholder="https://hooks.example.test/noc"
            className={`ltr ${input}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.secret}</span>
          <input
            name="secret"
            type="password"
            required
            minLength={16}
            maxLength={256}
            autoComplete="off"
            className={`ltr ${input}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.minSeverity}</span>
          <select name="minSeverity" defaultValue="warning" className={input}>
            {ConditionSeverityValues.map((sv) => (
              <option key={sv} value={sv}>
                {labels.severity[sv]}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
        >
          {labels.submit}
        </button>
        {state && 'error' in state ? (
          <span role="alert" className="text-xs text-sev-critical">
            {state.error}
          </span>
        ) : null}
        {state && 'created' in state ? (
          <span className="text-xs text-ok" data-testid="channel-created">
            {labels.created}
          </span>
        ) : null}
      </div>
    </form>
  );
}
