import type { EngagementStatus } from '@noc/shared';
import type { MessageKey } from '@/i18n/messages';

export const ENG_STATUS_LABEL: Record<EngagementStatus, MessageKey> = {
  draft: 'eng.status.draft',
  pending_approval: 'eng.status.pending_approval',
  approved: 'eng.status.approved',
  active: 'eng.status.active',
  paused: 'eng.status.paused',
  completed: 'eng.status.completed',
  cancelled: 'eng.status.cancelled',
  expired: 'eng.status.expired',
};

export const ENG_STATUS_STYLE: Record<EngagementStatus, string> = {
  draft: 'text-muted',
  pending_approval: 'text-sev-medium',
  approved: 'text-sev-low',
  active: 'text-sev-high',
  paused: 'text-sev-medium',
  completed: 'text-ok',
  cancelled: 'text-muted',
  expired: 'text-muted',
};

/** Targets a user may request from each state, by the permissions they hold. */
export function transitionTargets(
  status: EngagementStatus,
  perms: ReadonlySet<string>,
): EngagementStatus[] {
  const plan = perms.has('assessments.plan');
  const exec = perms.has('assessments.execute');
  const approve = perms.has('assessments.approve');
  const out: EngagementStatus[] = [];
  if (status === 'draft' && plan) out.push('pending_approval');
  if (status === 'approved' && exec) out.push('active');
  if (status === 'active' && exec) out.push('paused', 'completed');
  if (status === 'paused' && exec) out.push('active', 'completed');
  if (!['completed', 'cancelled', 'expired'].includes(status) && (plan || approve))
    out.push('cancelled');
  return out;
}
