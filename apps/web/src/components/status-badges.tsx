import type { CapabilityState } from '@noc/shared';

const CAP_STYLE: Record<CapabilityState, string> = {
  available: 'bg-ok/15 text-ok border-ok/30',
  degraded: 'bg-sev-medium/15 text-sev-medium border-sev-medium/30',
  disabled: 'bg-sev-high/15 text-sev-high border-sev-high/30',
  not_configured: 'bg-sev-low/15 text-sev-low border-sev-low/30',
  not_implemented: 'bg-border/60 text-muted border-border',
};

export function CapabilityBadge({ state, label }: { state: CapabilityState; label: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs ${CAP_STYLE[state]}`}>
      {label}
    </span>
  );
}

export function OutcomeBadge({ outcome }: { outcome: 'success' | 'denied' | 'failure' }) {
  const cls =
    outcome === 'success'
      ? 'text-ok'
      : outcome === 'denied'
        ? 'text-sev-high'
        : 'text-sev-critical';
  return <span className={`ltr text-xs font-medium ${cls}`}>{outcome}</span>;
}
