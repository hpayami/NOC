'use client';

import { useActionState, useRef } from 'react';
import {
  decideIpsPolicy,
  disableIpsPolicy,
  enableIpsPolicy,
  proposeIpsPolicy,
  type ActionState,
} from './actions';

const input = 'w-full rounded border border-border bg-surface-2 px-2 py-1 text-xs';
const btn =
  'rounded border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60';
const Err = ({ state }: { state: ActionState }) =>
  state?.error ? (
    <span role="alert" className="text-xs text-sev-critical">
      {state.error}
    </span>
  ) : null;

export function ProposePolicyForm({
  sensors,
  labels,
}: {
  sensors: Array<{ id: string; name: string; inlineCapable: boolean }>;
  labels: Record<
    | 'heading'
    | 'name'
    | 'sensor'
    | 'mode'
    | 'protected'
    | 'excluded'
    | 'rules'
    | 'justification'
    | 'rollbackPlan'
    | 'submit'
    | 'noSensors',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(proposeIpsPolicy, null);
  if (sensors.length === 0)
    return (
      <p className="rounded-lg border border-border bg-surface p-4 text-xs text-muted">
        {labels.noSensors}
      </p>
    );
  return (
    <form
      action={action}
      className="grid gap-2 rounded-lg border border-border bg-surface p-4 md:grid-cols-2"
    >
      <h2 className="text-sm font-medium md:col-span-2">{labels.heading}</h2>
      <label className="text-xs">
        <span className="text-muted">{labels.name}</span>
        <input name="name" required maxLength={256} className={input} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.sensor}</span>
        <select name="sensorId" className={`ltr ${input}`}>
          {sensors.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
              {s.inlineCapable ? '' : ' (not inline-capable)'}
            </option>
          ))}
        </select>
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.mode}</span>
        <select name="mode" className={`ltr ${input}`} defaultValue="ips_test">
          <option value="ips_test">ips_test</option>
          <option value="ips">ips</option>
        </select>
      </label>
      <label className="text-xs">
        <span className="text-muted">action</span>
        <select name="action" className={`ltr ${input}`} defaultValue="drop">
          <option value="drop">drop</option>
          <option value="reject">reject</option>
        </select>
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.protected}</span>
        <textarea
          name="protectedCidrs"
          required
          rows={2}
          dir="ltr"
          className={`ltr ${input}`}
          placeholder="10.20.0.0/16"
        />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.excluded}</span>
        <textarea name="excludedCidrs" rows={2} dir="ltr" className={`ltr ${input}`} />
      </label>
      <label className="text-xs md:col-span-2">
        <span className="text-muted">{labels.rules}</span>
        <textarea name="ruleIds" required rows={2} dir="ltr" className={`ltr ${input}`} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.justification}</span>
        <textarea name="justification" required minLength={10} rows={2} className={input} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.rollbackPlan}</span>
        <textarea name="rollbackPlan" required minLength={10} rows={2} className={input} />
      </label>
      <div className="flex items-center gap-2 md:col-span-2">
        <button type="submit" disabled={pending} className={btn}>
          {labels.submit}
        </button>
        <Err state={state} />
      </div>
    </form>
  );
}

export function DecisionForm({
  id,
  labels,
}: {
  id: string;
  labels: { approve: string; reject: string; justification: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(decideIpsPolicy, null);
  const ref = useRef<HTMLInputElement>(null);
  return (
    <form action={action} className="mt-2 flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
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
      <Err state={state} />
    </form>
  );
}

export function EnableForm({
  id,
  labels,
}: {
  id: string;
  labels: { hours: string; enable: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(enableIpsPolicy, null);
  return (
    <form action={action} className="mt-2 flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <label className="text-xs text-muted">
        {labels.hours}{' '}
        <input
          name="enabledForHours"
          type="number"
          min={1}
          max={72}
          defaultValue={24}
          className="w-16 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
        />
      </label>
      <button
        type="submit"
        disabled={pending}
        className={`${btn} border-sev-high/40 text-sev-high`}
      >
        {labels.enable}
      </button>
      <Err state={state} />
    </form>
  );
}

export function DisableForm({
  id,
  labels,
}: {
  id: string;
  labels: { reason: string; disable: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(disableIpsPolicy, null);
  return (
    <form action={action} className="mt-2 flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <input
        name="reason"
        required
        minLength={5}
        placeholder={labels.reason}
        className="w-48 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      />
      <button
        type="submit"
        disabled={pending}
        className={`${btn} border-sev-critical/40 text-sev-critical`}
      >
        {labels.disable}
      </button>
      <Err state={state} />
    </form>
  );
}
