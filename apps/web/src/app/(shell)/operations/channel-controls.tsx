'use client';

import { useActionState } from 'react';
import { setChannelEnabled, testChannel, type ChannelActionState } from './actions';

export function ChannelControls({
  id,
  enabled,
  labels,
}: {
  id: string;
  enabled: boolean;
  labels: Record<'test' | 'enable' | 'disable' | 'sent' | 'failed', string>;
}) {
  const [testState, testAction, testing] = useActionState<ChannelActionState, FormData>(
    testChannel,
    null,
  );
  const [toggleState, toggleAction, toggling] = useActionState<ChannelActionState, FormData>(
    setChannelEnabled,
    null,
  );
  const btn = 'rounded-md border border-border px-2 py-1 text-xs hover:text-fg disabled:opacity-60';
  const error =
    (testState && 'error' in testState && testState.error) ||
    (toggleState && 'error' in toggleState && toggleState.error) ||
    null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <form action={testAction}>
        <input type="hidden" name="id" value={id} />
        <button type="submit" disabled={testing} className={btn}>
          {labels.test}
        </button>
      </form>
      <form action={toggleAction}>
        <input type="hidden" name="id" value={id} />
        <input type="hidden" name="enabled" value={enabled ? 'false' : 'true'} />
        <button type="submit" disabled={toggling} className={btn}>
          {enabled ? labels.disable : labels.enable}
        </button>
      </form>
      {testState && 'delivery' in testState ? (
        <span
          className={`ltr text-xs ${testState.delivery.status === 'sent' ? 'text-ok' : 'text-sev-critical'}`}
          data-testid="channel-test-result"
        >
          {testState.delivery.status === 'sent' ? labels.sent : labels.failed}
          {testState.delivery.httpStatus !== null ? ` (HTTP ${testState.delivery.httpStatus})` : ''}
          {testState.delivery.error ? ` ${testState.delivery.error}` : ''}
        </span>
      ) : null}
      {error ? (
        <span role="alert" className="text-xs text-sev-critical">
          {error}
        </span>
      ) : null}
    </div>
  );
}
