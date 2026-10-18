'use client';

import { useActionState } from 'react';
import { scoreAsset, scoreBatch, type ActionState } from './actions';

const btn =
  'rounded border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2 disabled:opacity-60';
const Msg = ({ state }: { state: ActionState }) =>
  state && 'error' in state ? (
    <span role="alert" className="text-xs text-sev-critical">
      {state.error}
    </span>
  ) : state && 'info' in state ? (
    <span role="status" className="text-xs text-muted">
      {state.info}
    </span>
  ) : null;

export function ScoreForms({
  labels,
}: {
  labels: { assetId: string; score: string; batch: string };
}) {
  const [one, scoreOne, pendingOne] = useActionState<ActionState, FormData>(scoreAsset, null);
  const [all, scoreAll, pendingAll] = useActionState<ActionState, FormData>(scoreBatch, null);
  return (
    <div className="flex flex-wrap items-center gap-4">
      <form action={scoreOne} className="flex items-center gap-1">
        <input
          name="subjectId"
          required
          placeholder={labels.assetId}
          dir="ltr"
          className="ltr w-80 rounded border border-border bg-surface-2 px-2 py-1 text-xs"
        />
        <button type="submit" disabled={pendingOne} className={btn}>
          {labels.score}
        </button>
        <Msg state={one} />
      </form>
      <form action={scoreAll} className="flex items-center gap-1">
        <button type="submit" disabled={pendingAll} className={btn}>
          {labels.batch}
        </button>
        <Msg state={all} />
      </form>
    </div>
  );
}
