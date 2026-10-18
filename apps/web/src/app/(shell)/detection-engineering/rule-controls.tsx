'use client';

import { useActionState } from 'react';
import { deployRule, setRuleTargets, type RuleActionState } from './actions';

const btn = 'rounded-md border border-border px-2 py-1 text-xs text-muted hover:text-fg';

export function DeployButton({ id, label }: { id: string; label: string }) {
  const [state, action, pending] = useActionState<RuleActionState, FormData>(deployRule, null);
  return (
    <form action={action} className="inline">
      <input type="hidden" name="id" value={id} />
      <button type="submit" disabled={pending} className={btn}>
        {label}
      </button>
      {state && 'error' in state ? (
        <span role="alert" className="ms-2 text-[10px] text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}

export function TargetsForm({
  id,
  sites,
  labels,
}: {
  id: string;
  sites: string[];
  labels: { placeholder: string; save: string };
}) {
  const [state, action, pending] = useActionState<RuleActionState, FormData>(setRuleTargets, null);
  return (
    <form action={action} className="mt-1 flex items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <input
        name="sites"
        defaultValue={sites.join(', ')}
        placeholder={labels.placeholder}
        className="ltr w-40 rounded-md border border-border bg-surface-2 px-2 py-0.5 text-[11px]"
      />
      <button type="submit" disabled={pending} className={btn}>
        {labels.save}
      </button>
      {state && 'error' in state ? (
        <span role="alert" className="text-[10px] text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}
