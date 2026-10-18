import Link from 'next/link';
import type { ConditionSeverity, PlatformConditions } from '@noc/shared';

const TONE: Record<ConditionSeverity, string> = {
  critical: 'border-sev-critical text-sev-critical',
  warning: 'border-sev-medium text-sev-medium',
  info: 'border-border text-muted',
};

/** Conditions an operator should act on, plus what every check concluded. Server component. */
export function ConditionsPanel({
  data,
  labels,
}: {
  data: PlatformConditions;
  labels: {
    none: string;
    checks: string;
    ok: string;
    failing: string;
    unavailable: string;
    open: string;
    severity: Record<ConditionSeverity, string>;
  };
}) {
  const tally = { ok: 0, failing: 0, unavailable: 0 };
  for (const c of data.checks) tally[c.status]++;
  return (
    <div className="space-y-3">
      {data.conditions.length === 0 ? (
        <p className="rounded-md border border-border bg-surface p-3 text-sm text-ok">
          {labels.none}
        </p>
      ) : (
        <ul className="space-y-2" data-testid="conditions">
          {data.conditions.map((c) => (
            <li
              key={c.id}
              className={`flex flex-wrap items-start justify-between gap-2 rounded-md border bg-surface p-3 ${TONE[c.severity]}`}
            >
              <div className="min-w-0">
                <p className="text-sm font-medium">
                  <span className="me-2 rounded border border-current px-1.5 py-0.5 text-[10px] uppercase">
                    {labels.severity[c.severity]}
                  </span>
                  {c.title}
                  <span className="ltr ms-2 text-xs text-muted">{c.id}</span>
                </p>
                <p className="ltr mt-1 text-xs text-muted">{c.detail}</p>
              </div>
              {c.link ? (
                <Link href={c.link} className="text-xs underline">
                  {labels.open}
                </Link>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-muted" data-testid="checks-summary">
        {labels.checks}: <span className="text-ok">{tally.ok}</span> {labels.ok} ·{' '}
        <span className={tally.failing ? 'text-sev-critical' : ''}>{tally.failing}</span>{' '}
        {labels.failing} ·{' '}
        <span className={tally.unavailable ? 'text-sev-low' : ''}>{tally.unavailable}</span>{' '}
        {labels.unavailable}
      </p>
    </div>
  );
}
