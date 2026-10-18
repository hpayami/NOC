'use client';

import { useActionState } from 'react';
import { requestValidation, type ValidateState } from './actions';

export function ValidateForm({
  rules,
  sensors,
  labels,
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
    | 'noSensors',
    string
  >;
}) {
  const [state, action, pending] = useActionState<ValidateState, FormData>(requestValidation, null);
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form
      action={action}
      className="space-y-2 rounded-lg border border-border bg-surface p-4"
      data-testid="bt-validate"
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
            {state && 'queued' in state ? (
              <span className="text-xs text-ok">{labels.queued}</span>
            ) : null}
          </div>
        </>
      )}
    </form>
  );
}
