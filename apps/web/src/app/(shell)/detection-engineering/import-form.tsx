'use client';

import { useActionState } from 'react';
import { importRules, type ImportState } from './actions';

export function ImportRulesForm({
  labels,
}: {
  labels: Record<
    'title' | 'source' | 'ruleSet' | 'license' | 'content' | 'submit' | 'result',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ImportState, FormData>(importRules, null);
  const input = 'w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form
      action={action}
      className="grid gap-3 rounded-lg border border-border bg-surface p-5 md:grid-cols-3"
    >
      <h2 className="font-medium md:col-span-3">{labels.title}</h2>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.source}</span>
        <select name="source" className={input} defaultValue="et_open">
          <option value="et_open">et_open</option>
          <option value="custom">custom</option>
          <option value="vendor">vendor</option>
        </select>
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.ruleSet}</span>
        <input name="ruleSet" required maxLength={256} dir="ltr" className={`ltr ${input}`} />
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.license}</span>
        <input
          name="license"
          required
          maxLength={256}
          dir="ltr"
          className={`ltr ${input}`}
          placeholder="BSD-2-Clause"
        />
      </label>
      <label className="space-y-1 text-sm md:col-span-3">
        <span className="text-muted">{labels.content}</span>
        <textarea name="content" required rows={6} dir="ltr" className={`ltr font-mono ${input}`} />
      </label>
      <div className="flex items-center gap-3 md:col-span-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
        >
          {labels.submit}
        </button>
        {state && 'result' in state ? (
          <span className="ltr text-xs text-muted" role="status">
            {labels.result}: parsed {state.result.parsed}, imported {state.result.imported}, updated{' '}
            {state.result.updated}, unchanged {state.result.unchanged}, errors{' '}
            {state.result.errorCount}
          </span>
        ) : state && 'error' in state ? (
          <span role="alert" className="text-xs text-sev-critical">
            {state.error}
          </span>
        ) : null}
      </div>
    </form>
  );
}
