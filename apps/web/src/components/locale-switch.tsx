import { setLocaleAction } from './locale-actions';

export function LocaleSwitch({ label }: { label: string }) {
  return (
    <form action={setLocaleAction}>
      <button
        type="submit"
        className="rounded-md border border-border px-2 py-1 text-xs text-muted hover:text-fg"
        aria-label="Switch language"
      >
        {label}
      </button>
    </form>
  );
}
