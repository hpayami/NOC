'use client';

import { useActionState } from 'react';
import { PASSWORD_MAX_LENGTH } from '@noc/shared';
import { loginAction, type LoginState } from './actions';

interface Labels {
  email: string;
  password: string;
  submit: string;
  submitting: string;
  errors: Record<string, string>;
}

export function LoginForm({
  labels,
  initialError,
}: {
  labels: Labels;
  initialError: string | null;
}) {
  const [state, action, pending] = useActionState<LoginState, FormData>(loginAction, {
    error: null,
  });
  const error = state.error ? labels.errors[state.error] : initialError;

  return (
    <form action={action} className="space-y-5" noValidate>
      <div className="space-y-1.5">
        <label htmlFor="email" className="block text-sm text-muted">
          {labels.email}
        </label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="username"
          required
          maxLength={254}
          dir="ltr"
          className="ltr w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-fg placeholder:text-muted"
        />
      </div>
      <div className="space-y-1.5">
        <label htmlFor="password" className="block text-sm text-muted">
          {labels.password}
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={PASSWORD_MAX_LENGTH}
          dir="ltr"
          className="ltr w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-fg"
        />
      </div>
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-fg"
        >
          {error}
        </p>
      ) : null}
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded-md bg-accent px-4 py-2 font-medium text-bg transition hover:brightness-110 disabled:opacity-60"
      >
        {pending ? labels.submitting : labels.submit}
      </button>
    </form>
  );
}
