import type { ResponseActionKind } from '../enums';
import type { Permission } from '../rbac';

/** Number of distinct approvers required before a response action may execute. */
export function requiredApprovals(kind: ResponseActionKind): number {
  switch (kind) {
    case 'enable_inline_prevention':
    case 'isolate_endpoint':
      return 2;
    case 'recommend_isolation':
    case 'escalate':
    case 'collect_evidence':
      return 0; // advisory / non-state-changing
    default:
      return 1;
  }
}

export type ApprovalCheck = { ok: true } | { ok: false; code: string; message: string };

export function checkApproval(input: {
  kind: ResponseActionKind;
  status: string;
  proposedBy: string;
  approverId: string;
  approverPermissions: ReadonlySet<Permission>;
  priorApproverIds: readonly string[];
  expiresAt: Date | null;
  now: Date;
}): ApprovalCheck {
  if (input.status !== 'pending_approval') {
    return { ok: false, code: 'bad_state', message: 'Action is not awaiting approval' };
  }
  if (input.expiresAt && input.expiresAt.getTime() <= input.now.getTime()) {
    return { ok: false, code: 'expired', message: 'Action has expired' };
  }
  const needed: Permission =
    input.kind === 'enable_inline_prevention' ? 'ips.approve' : 'response.approve';
  if (!input.approverPermissions.has(needed)) {
    return { ok: false, code: 'forbidden', message: `Missing permission ${needed}` };
  }
  if (input.approverId === input.proposedBy) {
    return {
      ok: false,
      code: 'self_approval',
      message: 'Proposer cannot approve their own action',
    };
  }
  if (input.priorApproverIds.includes(input.approverId)) {
    return {
      ok: false,
      code: 'duplicate_approver',
      message: 'Approver has already decided on this action',
    };
  }
  return { ok: true };
}
