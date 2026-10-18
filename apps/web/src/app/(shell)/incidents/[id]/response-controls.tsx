'use client';

import { useActionState, useRef } from 'react';
import { RESPONSE_TARGET_TYPES, type ResponseActionKind } from '@noc/shared';
import {
  decideResponseAction,
  proposeResponseAction,
  runResponseAction,
  type ActionState,
} from '../actions';

const input = 'w-full rounded border border-border bg-surface-2 px-2 py-1 text-xs';
const btn =
  'rounded border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60';

export function ProposeForm({
  incidentId,
  kinds,
  labels,
}: {
  incidentId: string;
  kinds: Array<{ kind: ResponseActionKind; label: string; available: boolean; approvals: number }>;
  labels: Record<
    'heading' | 'kind' | 'targetType' | 'target' | 'justification' | 'rollbackPlan' | 'submit',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    proposeResponseAction,
    null,
  );
  return (
    <form action={action} className="grid gap-2 rounded-lg border border-border bg-surface p-4">
      <h3 className="text-sm font-medium">{labels.heading}</h3>
      <input type="hidden" name="incidentId" value={incidentId} />
      <label className="text-xs">
        <span className="text-muted">{labels.kind}</span>
        <select name="kind" className={`ltr ${input}`} defaultValue="collect_evidence">
          {kinds.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.kind} · {k.label} · {k.approvals}✓{k.available ? '' : ' · ∅'}
            </option>
          ))}
        </select>
      </label>
      <div className="grid grid-cols-3 gap-2">
        <label className="text-xs">
          <span className="text-muted">{labels.targetType}</span>
          <select name="targetType" className={`ltr ${input}`} defaultValue="ip">
            {RESPONSE_TARGET_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="col-span-2 text-xs">
          <span className="text-muted">{labels.target}</span>
          <input name="targetRef" required maxLength={512} dir="ltr" className={`ltr ${input}`} />
        </label>
      </div>
      <label className="text-xs">
        <span className="text-muted">{labels.justification}</span>
        <textarea name="justification" required minLength={10} rows={2} className={input} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.rollbackPlan}</span>
        <textarea name="rollbackPlan" required minLength={10} rows={2} className={input} />
      </label>
      <div className="flex items-center gap-2">
        <button type="submit" disabled={pending} className={btn}>
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

export function DecisionForm({
  actionId,
  labels,
}: {
  actionId: string;
  labels: { approve: string; reject: string; justification: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    decideResponseAction,
    null,
  );
  const ref = useRef<HTMLInputElement>(null);
  return (
    <form action={action} className="mt-2 flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={actionId} />
      <input type="hidden" name="decision" ref={ref} />
      <input
        name="justification"
        required
        minLength={5}
        placeholder={labels.justification}
        className="w-48 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      />
      {(['approve', 'reject'] as const).map((d) => (
        <button
          key={d}
          type="submit"
          disabled={pending}
          onClick={() => {
            if (ref.current) ref.current.value = d;
          }}
          className={btn}
        >
          {labels[d]}
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

export function RunForm({
  actionId,
  op,
  label,
}: {
  actionId: string;
  op: 'execute' | 'rollback';
  label: string;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(runResponseAction, null);
  return (
    <form action={action} className="mt-2 flex items-center gap-2">
      <input type="hidden" name="id" value={actionId} />
      <input type="hidden" name="op" value={op} />
      <button type="submit" disabled={pending} className={btn}>
        {label}
      </button>
      {state?.error ? (
        <span role="alert" className="text-xs text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}
