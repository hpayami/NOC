'use client';

import { useActionState } from 'react';
import {
  requestSchedule,
  requestValidation,
  setScheduleEnabled,
  type ScheduleState,
  type ValidateState,
} from './actions';

export function ValidateForm({
  rules,
  sensors,
  labels,
  mode = 'once',
}: {
  rules: Array<{ id: string; label: string }>;
  sensors: Array<{ id: string; label: string }>;
  labels: Record<
    | 'heading'
    | 'hint'
    | 'rule'
    | 'sensor'
    | 'sample'
    | 'note'
    | 'submit'
    | 'queued'
    | 'noRules'
    | 'noSensors'
    | 'interval',
    string
  >;
  mode?: 'once' | 'schedule';
}) {
  type FormState = ValidateState | ScheduleState;
  const submit = async (prev: FormState, data: FormData): Promise<FormState> =>
    mode === 'schedule'
      ? requestSchedule(prev as ScheduleState, data)
      : requestValidation(prev as ValidateState, data);
  const [state, action, pending] = useActionState<FormState, FormData>(submit, null);
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form
      action={action}
      className="space-y-2 rounded-lg border border-border bg-surface p-4"
      data-testid={mode === 'schedule' ? 'bt-schedule' : 'bt-validate'}
    >
      <h3 className="font-medium">{labels.heading}</h3>
      <p className="text-xs text-muted">{labels.hint}</p>
      {rules.length === 0 ? (
        <p className="text-xs text-muted">{labels.noRules}</p>
      ) : sensors.length === 0 ? (
        <p className="text-xs text-muted">{labels.noSensors}</p>
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.rule}</span>
              <select name="ruleId" required className={`ltr ${input}`}>
                {rules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.sensor}</span>
              <select name="sensorId" required className={`ltr ${input}`}>
                {sensors.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.sample}</span>
              <input
                name="sampleRef"
                required
                pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
                placeholder="c2-beacon.pcap"
                className={`ltr ${input}`}
              />
            </label>
            {mode === 'schedule' ? (
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">{labels.interval}</span>
                <input
                  name="intervalDays"
                  type="number"
                  min={1}
                  max={30}
                  defaultValue={7}
                  className={`ltr ${input}`}
                />
              </label>
            ) : null}
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.note}</span>
              <input name="note" maxLength={1024} className={input} />
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
              <span role="alert" className="ltr text-xs text-sev-critical">
                {state.error}
              </span>
            ) : null}
            {state && ('queued' in state || 'saved' in state) ? (
              <span className="text-xs text-ok">{labels.queued}</span>
            ) : null}
          </div>
        </>
      )}
    </form>
  );
}

export function ScheduleToggle({
  id,
  enabled,
  labels,
}: {
  id: string;
  enabled: boolean;
  labels: Record<'enable' | 'disable', string>;
}) {
  const [state, action, pending] = useActionState<ScheduleState, FormData>(
    setScheduleEnabled,
    null,
  );
  return (
    <form action={action} className="inline-flex items-center gap-2">
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="enabled" value={enabled ? 'false' : 'true'} />
      <button
        type="submit"
        disabled={pending}
        className="rounded-md border border-border px-2 py-1 text-xs hover:text-fg disabled:opacity-60"
      >
        {enabled ? labels.disable : labels.enable}
      </button>
      {state && 'error' in state ? (
        <span role="alert" className="ltr text-xs text-sev-critical">
          {state.error}
        </span>
      ) : null}
    </form>
  );
}
