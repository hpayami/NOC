'use client';

import { useActionState, useState } from 'react';
import { ConditionSeverityValues } from '@noc/shared';
import { createChannel, type CreateChannelState } from './actions';

export function CreateChannelForm({
  labels,
}: {
  labels: Record<
    | 'heading'
    | 'hint'
    | 'name'
    | 'url'
    | 'secret'
    | 'minSeverity'
    | 'submit'
    | 'created'
    | 'kind'
    | 'kindWebhook'
    | 'kindEmail'
    | 'host'
    | 'port'
    | 'starttls'
    | 'username'
    | 'password'
    | 'from'
    | 'recipients'
    | 'emailHint',
    string
  > & { severity: Record<(typeof ConditionSeverityValues)[number], string> };
}) {
  const [state, action, pending] = useActionState<CreateChannelState, FormData>(
    createChannel,
    null,
  );
  const [kind, setKind] = useState<'webhook' | 'email'>('webhook');
  const input = 'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form action={action} className="space-y-3 rounded-lg border border-border bg-surface p-4">
      <h3 className="font-medium">{labels.heading}</h3>
      <p className="text-xs text-muted">{kind === 'email' ? labels.emailHint : labels.hint}</p>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.kind}</span>
          <select
            name="kind"
            value={kind}
            onChange={(e) => setKind(e.target.value === 'email' ? 'email' : 'webhook')}
            className={`ltr ${input}`}
            data-testid="channel-kind"
          >
            <option value="webhook">{labels.kindWebhook}</option>
            <option value="email">{labels.kindEmail}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">{labels.name}</span>
          <input name="name" required maxLength={200} className={input} />
        </label>
        {kind === 'email' ? (
          <>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.host}</span>
              <input
                name="host"
                required
                maxLength={253}
                placeholder="mail.example.test"
                className={`ltr ${input}`}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.port}</span>
              <input
                name="port"
                type="number"
                min={1}
                max={65535}
                defaultValue={587}
                className={`ltr ${input}`}
              />
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input name="starttls" type="checkbox" defaultChecked />
              <span className="text-muted">{labels.starttls}</span>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.username}</span>
              <input
                name="username"
                maxLength={256}
                autoComplete="off"
                className={`ltr ${input}`}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.password}</span>
              <input
                name="password"
                type="password"
                maxLength={256}
                autoComplete="new-password"
                className={`ltr ${input}`}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">{labels.from}</span>
              <input name="from" type="email" required maxLength={256} className={`ltr ${input}`} />
            </label>
            <label className="flex flex-col gap-1 text-sm md:col-span-2">
              <span className="text-muted">{labels.recipients}</span>
              <input
                name="recipients"
                required
                placeholder="soc@example.test, ops@example.test"
                className={`ltr ${input}`}
              />
            </label>
          </>
        ) : null}
        <label className={`flex flex-col gap-1 text-sm ${kind === 'email' ? 'hidden' : ''}`}>
          <span className="text-muted">{labels.url}</span>
          <input
            name="url"
            type="url"
            required={kind === 'webhook'}
            placeholder="https://hooks.example.test/noc"
            className={`ltr ${input}`}
          />
        </label>
        <label className={`flex flex-col gap-1 text-sm ${kind === 'email' ? 'hidden' : ''}`}>
          <span className="text-muted">{labels.secret}</span>
          <input
            name="secret"
            type="password"
            required={kind === 'webhook'}
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
