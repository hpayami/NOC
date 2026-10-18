import type { AlertStatus } from '../enums';

export const ALERT_ACTIONS = [
  'acknowledge',
  'investigate',
  'escalate',
  'suppress',
  'false_positive',
  'resolve',
  'reopen',
] as const;
export type AlertAction = (typeof ALERT_ACTIONS)[number];

const TARGET: Record<AlertAction, AlertStatus> = {
  acknowledge: 'acknowledged',
  investigate: 'investigating',
  escalate: 'escalated',
  suppress: 'suppressed',
  false_positive: 'false_positive',
  resolve: 'resolved',
  reopen: 'new',
};

const ALLOWED: Record<AlertStatus, readonly AlertAction[]> = {
  new: ['acknowledge', 'investigate', 'escalate', 'suppress', 'false_positive', 'resolve'],
  acknowledged: ['investigate', 'escalate', 'suppress', 'false_positive', 'resolve'],
  investigating: ['escalate', 'suppress', 'false_positive', 'resolve'],
  escalated: ['investigate', 'resolve', 'false_positive'],
  suppressed: ['reopen', 'resolve', 'false_positive'],
  false_positive: ['reopen'],
  resolved: ['reopen'],
};

/** Dispositions that end an alert's life as an open item. */
export const CLOSED_ALERT_STATUSES: readonly AlertStatus[] = ['resolved', 'false_positive'];

export type AlertTransition =
  { ok: true; to: AlertStatus; requiresNote: boolean } | { ok: false; message: string };

/**
 * Alert triage state machine. False-positive and resolve dispositions and reopening require a
 * note so the queue history explains itself; suppression needs an expiry (checked by the API).
 */
export function validateAlertTransition(
  from: AlertStatus,
  action: AlertAction,
  note?: string | null,
): AlertTransition {
  if (!ALLOWED[from].includes(action))
    return { ok: false, message: `Action "${action}" is not allowed from status "${from}"` };
  const requiresNote = action === 'false_positive' || action === 'resolve' || action === 'reopen';
  if (requiresNote && !(note && note.trim().length >= 5))
    return { ok: false, message: `Action "${action}" requires a note` };
  return { ok: true, to: TARGET[action], requiresNote };
}
