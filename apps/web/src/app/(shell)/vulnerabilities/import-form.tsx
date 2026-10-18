'use client';

import { useActionState } from 'react';
import { VulnerabilityFeedFormatValues } from '@noc/shared';
import { importVulnerabilities, type ImportState } from './actions';

export function ImportCatalogForm({
  labels,
}: {
  labels: Record<'heading' | 'hint' | 'format' | 'submit' | 'result', string>;
}) {
  const [state, action, pending] = useActionState<ImportState, FormData>(
    importVulnerabilities,
    null,
  );
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form action={action} className="space-y-2 rounded-lg border border-border bg-surface p-4">
      <h2 className="font-medium">{labels.heading}</h2>
      <p className="text-xs text-muted">{labels.hint}</p>
      <label className="flex items-center gap-2 text-sm">
        <span className="text-muted">{labels.format}</span>
        <select name="format" defaultValue="nvd_2" className={`ltr ${input}`}>
          {VulnerabilityFeedFormatValues.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>
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
          <span className="ltr text-xs text-muted" data-testid="vuln-import-result">
            {labels.result}: parsed {state.result.parsed}, imported {state.result.imported}, updated{' '}
            {state.result.updated}, unchanged {state.result.unchanged}, findings enriched{' '}
            {state.result.findingsEnriched}, errors {state.result.errorCount}
          </span>
        ) : null}
      </div>
    </form>
  );
}
