'use client';

import { useActionState } from 'react';
import { IndicatorFeedFormatValues, SeverityValues } from '@noc/shared';
import { importIndicators, revokeIndicator, type ImportState, type RevokeState } from './actions';

export function ImportIndicatorsForm({
  labels,
}: {
  labels: Record<
    'heading' | 'hint' | 'format' | 'source' | 'severity' | 'submit' | 'result',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ImportState, FormData>(importIndicators, null);
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form action={action} className="space-y-2 rounded-lg border border-border bg-surface p-4">
      <h2 className="font-medium">{labels.heading}</h2>
      <p className="text-xs text-muted">{labels.hint}</p>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2">
          <span className="text-muted">{labels.format}</span>
          <select name="format" defaultValue="noc" className={`ltr ${input}`}>
            {IndicatorFeedFormatValues.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-muted">{labels.source}</span>
          <input name="source" required maxLength={256} className={`ltr ${input}`} />
        </label>
        <label className="flex items-center gap-2">
          <span className="text-muted">{labels.severity}</span>
          <select name="defaultSeverity" defaultValue="medium" className={`ltr ${input}`}>
            {SeverityValues.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>
      <textarea
        name="content"
        rows={6}
        required
        className={`ltr w-full font-mono text-xs ${input}`}
      />
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
        {state && 'result' in state ? (
          <span className="ltr text-xs text-muted" data-testid="ti-import-result">
            {labels.result}: parsed {state.result.parsed}, imported {state.result.imported}, updated{' '}
            {state.result.updated}, unchanged {state.result.unchanged}, revoked{' '}
            {state.result.revoked}, retro-matches {state.result.retroMatches} (
            {state.result.retroWindowHours} h), errors {state.result.errorCount}
            {state.result.errors.length ? ` — ${state.result.errors.join('; ')}` : ''}
          </span>
        ) : null}
      </div>
    </form>
  );
}

export function RevokeButton({
  id,
  labels,
}: {
  id: string;
  labels: Record<'revoke' | 'done', string>;
}) {
  const [state, action, pending] = useActionState<RevokeState, FormData>(revokeIndicator, null);
  return (
    <form action={action} className="inline-flex items-center gap-2">
      <input type="hidden" name="id" value={id} />
      <button
        type="submit"
        disabled={pending || (state !== null && 'revoked' in state)}
        className="rounded-md border border-border px-2 py-1 text-xs hover:text-fg disabled:opacity-60"
      >
        {state && 'revoked' in state ? labels.done : labels.revoke}
      </button>
      {state && 'error' in state ? (
        <span role="alert" className="text-xs text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}
