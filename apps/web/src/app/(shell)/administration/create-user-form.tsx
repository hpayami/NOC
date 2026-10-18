'use client';

import { useActionState } from 'react';
import { PASSWORD_MIN_LENGTH } from '@noc/shared';
import { createUserAction, type CreateUserState } from './actions';

export function CreateUserForm({
  roles,
  labels,
}: {
  roles: { key: string; name: string }[];
  labels: Record<'email' | 'displayName' | 'password' | 'role' | 'submit', string>;
}) {
  const [state, action, pending] = useActionState<CreateUserState, FormData>(createUserAction, {
    error: null,
  });
  const input = 'w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm';
  return (
    <form
      action={action}
      className="grid max-w-2xl gap-4 rounded-lg border border-border bg-surface p-5 md:grid-cols-2"
    >
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.email}</span>
        <input
          name="email"
          type="email"
          required
          maxLength={254}
          dir="ltr"
          className={`ltr ${input}`}
        />
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">{labels.displayName}</span>
        <input name="displayName" required maxLength={128} className={input} />
      </label>
      <label className="space-y-1 text-sm">
        <span className="text-muted">
          {labels.password} (≥ {PASSWORD_MIN_LENGTH})
        </span>
        <input
          name="password"
          type="password"
          required
          minLength={PASSWORD_MIN_LENGTH}
          autoComplete="new-password"
          dir="ltr"
          className={`ltr ${input}`}
        />
      </label>
      <fieldset className="space-y-1 text-sm">
        <legend className="text-muted">{labels.role}</legend>
        <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
          {roles.map((r) => (
            <label key={r.key} className="flex items-center gap-2">
              <input type="checkbox" name="roles" value={r.key} />
              <span>{r.name}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {state.error ? (
        <p role="alert" className="md:col-span-2 text-sm text-sev-critical">
          {state.error}
        </p>
      ) : null}
      <div className="md:col-span-2">
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
        >
          {labels.submit}
        </button>
      </div>
    </form>
  );
}
