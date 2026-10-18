'use client';

import { useActionState, useRef } from 'react';
import { AssessmentTechniqueValues, type EngagementStatus } from '@noc/shared';
import {
  createEngagement,
  createRun,
  decideEngagement,
  runOp,
  transitionEngagement,
  updateFinding,
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
const local = (d: Date) =>
  new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

export function NewEngagementForm({
  labels,
}: {
  labels: Record<
    | 'heading'
    | 'reference'
    | 'org'
    | 'authRef'
    | 'objective'
    | 'includeCidrs'
    | 'includeAddresses'
    | 'excludeCidrs'
    | 'techniques'
    | 'windowStart'
    | 'windowEnd'
    | 'stopConditions'
    | 'emergencyContact'
    | 'submit',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createEngagement, null);
  const now = new Date();
  return (
    <form
      action={action}
      className="grid gap-2 rounded-lg border border-border bg-surface p-4 md:grid-cols-2"
    >
      <h2 className="text-sm font-medium md:col-span-2">{labels.heading}</h2>
      <label className="text-xs">
        <span className="text-muted">{labels.reference}</span>
        <input name="reference" required maxLength={256} className={`ltr ${input}`} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.org}</span>
        <input name="authorizingOrganization" required maxLength={256} className={input} />
      </label>
      <label className="text-xs md:col-span-2">
        <span className="text-muted">{labels.authRef}</span>
        <input name="authorizationReference" required maxLength={256} className={`ltr ${input}`} />
      </label>
      <label className="text-xs md:col-span-2">
        <span className="text-muted">{labels.objective}</span>
        <textarea name="objective" required minLength={10} rows={2} className={input} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.includeCidrs}</span>
        <textarea name="includeCidrs" rows={2} dir="ltr" className={`ltr ${input}`} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.includeAddresses}</span>
        <textarea name="includeAddresses" rows={2} dir="ltr" className={`ltr ${input}`} />
      </label>
      <label className="text-xs md:col-span-2">
        <span className="text-muted">{labels.excludeCidrs}</span>
        <textarea name="excludeCidrs" rows={1} dir="ltr" className={`ltr ${input}`} />
      </label>
      <fieldset className="text-xs md:col-span-2">
        <legend className="text-muted">{labels.techniques}</legend>
        <div className="mt-1 flex flex-wrap gap-3">
          {AssessmentTechniqueValues.map((t) => (
            <label key={t} className="ltr flex items-center gap-1">
              <input
                type="checkbox"
                name="technique"
                value={t}
                defaultChecked={t === 'host_discovery' || t === 'service_fingerprint'}
              />{' '}
              {t}
            </label>
          ))}
        </div>
      </fieldset>
      <label className="text-xs">
        <span className="text-muted">{labels.windowStart}</span>
        <input
          name="windowStart"
          type="datetime-local"
          required
          defaultValue={local(now)}
          className={`ltr ${input}`}
        />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.windowEnd}</span>
        <input
          name="windowEnd"
          type="datetime-local"
          required
          defaultValue={local(new Date(now.getTime() + 7 * 86_400_000))}
          className={`ltr ${input}`}
        />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.stopConditions}</span>
        <textarea name="stopConditions" required rows={2} className={input} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.emergencyContact}</span>
        <input name="emergencyContact" required maxLength={256} className={`ltr ${input}`} />
      </label>
      <input type="hidden" name="maxConcurrency" value={2} />
      <input type="hidden" name="maxRequestsPerSecond" value={5} />
      <div className="flex items-center gap-2 md:col-span-2">
        <button type="submit" disabled={pending} className={btn}>
          {labels.submit}
        </button>
        <Err state={state} />
      </div>
    </form>
  );
}

export function TransitionForm({
  id,
  targets,
  labels,
}: {
  id: string;
  targets: EngagementStatus[];
  labels: { reason: string; states: Record<string, string> };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    transitionEngagement,
    null,
  );
  const ref = useRef<HTMLInputElement>(null);
  if (targets.length === 0) return null;
  return (
    <form action={action} className="flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="to" ref={ref} />
      <input
        name="reason"
        placeholder={labels.reason}
        className="w-56 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      />
      {targets.map((to) => (
        <button
          key={to}
          type="submit"
          disabled={pending}
          onClick={() => {
            if (ref.current) ref.current.value = to;
          }}
          className={btn}
        >
          → {labels.states[to] ?? to}
        </button>
      ))}
      <Err state={state} />
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
  const [state, action, pending] = useActionState<ActionState, FormData>(decideEngagement, null);
  const ref = useRef<HTMLInputElement>(null);
  return (
    <form action={action} className="flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="decision" ref={ref} />
      <input
        name="justification"
        required
        minLength={10}
        placeholder={labels.justification}
        className="w-56 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
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

export function NewRunForm({
  id,
  techniques,
  labels,
}: {
  id: string;
  techniques: Array<{ technique: string; executable: boolean }>;
  labels: { technique: string; ports: string; dryRun: string; submit: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createRun, null);
  return (
    <form
      action={action}
      className="flex flex-wrap items-end gap-2 rounded-lg border border-border bg-surface p-3"
    >
      <input type="hidden" name="id" value={id} />
      <label className="text-xs">
        <span className="text-muted">{labels.technique}</span>
        <select name="technique" className={`ltr ${input}`}>
          {techniques.map((t) => (
            <option key={t.technique} value={t.technique}>
              {t.technique}
              {t.executable ? '' : ' ∅'}
            </option>
          ))}
        </select>
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.ports}</span>
        <input name="ports" dir="ltr" placeholder="22,80,443" className={`ltr ${input}`} />
      </label>
      <label className="text-xs">
        <span className="text-muted">{labels.dryRun}</span>
        <select name="dryRun" className={`ltr ${input}`} defaultValue="true">
          <option value="true">dry run</option>
          <option value="false">live</option>
        </select>
      </label>
      <button type="submit" disabled={pending} className={btn}>
        {labels.submit}
      </button>
      <Err state={state} />
    </form>
  );
}

export function RunButton({
  id,
  runId,
  op,
  label,
}: {
  id: string;
  runId: string;
  op: 'execute' | 'cancel';
  label: string;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(runOp, null);
  return (
    <form action={action} className="inline-flex items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="runId" value={runId} />
      <input type="hidden" name="op" value={op} />
      <button type="submit" disabled={pending} className={btn}>
        {label}
      </button>
      <Err state={state} />
    </form>
  );
}

export function FindingForm({
  id,
  statuses,
  labels,
}: {
  id: string;
  statuses: string[];
  labels: { note: string; submit: string };
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(updateFinding, null);
  return (
    <form action={action} className="mt-1 flex flex-wrap items-center gap-1">
      <input type="hidden" name="id" value={id} />
      <select
        name="status"
        className="ltr rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      >
        {statuses.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
      <input
        name="note"
        required
        minLength={5}
        placeholder={labels.note}
        className="w-56 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
      />
      <button type="submit" disabled={pending} className={btn}>
        {labels.submit}
      </button>
      <Err state={state} />
    </form>
  );
}
