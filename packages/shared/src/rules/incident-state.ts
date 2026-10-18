import type { IncidentStatus, IncidentType } from '../enums';

const STANDARD_FLOW: IncidentStatus[] = [
  'new',
  'triage',
  'investigation',
  'containment',
  'eradication',
  'recovery',
  'closed',
];

type Edge = {
  to: IncidentStatus;
  requiresReason?: boolean;
  requiresPermission?: 'incidents.close';
};

/**
 * Allowed transitions. The default lifecycle is the forward chain
 * New → Triage → Investigation → Containment → Eradication → Recovery → Closed.
 * Controlled deviations (early closure, reopen, type-specific skips) always require a reason.
 */
function edgesFrom(type: IncidentType, from: IncidentStatus): Edge[] {
  const idx = STANDARD_FLOW.indexOf(from);
  const edges: Edge[] = [];
  const next = STANDARD_FLOW[idx + 1];
  if (next && from !== 'closed')
    edges.push({ to: next, requiresPermission: next === 'closed' ? 'incidents.close' : undefined });

  switch (from) {
    case 'triage':
    case 'investigation':
      // Benign / duplicate / false-positive closure.
      edges.push({ to: 'closed', requiresReason: true, requiresPermission: 'incidents.close' });
      break;
    case 'recovery':
      edges.push({ to: 'investigation', requiresReason: true }); // recurrence found
      break;
    case 'closed':
      edges.push({
        to: 'investigation',
        requiresReason: true,
        requiresPermission: 'incidents.close',
      }); // reopen
      break;
    default:
      break;
  }

  if (type === 'noc_outage' && from === 'investigation') {
    // Outages usually have no eradication phase: go straight to recovery.
    edges.push({ to: 'recovery', requiresReason: true });
  }
  if (type === 'policy_violation' && from === 'investigation') {
    edges.push({ to: 'eradication', requiresReason: true });
  }
  return edges;
}

export type TransitionResult =
  | { ok: true; requiresPermission?: 'incidents.close'; deviation: boolean }
  | { ok: false; code: 'same_state' | 'not_allowed' | 'reason_required'; message: string };

export function validateIncidentTransition(input: {
  type: IncidentType;
  from: IncidentStatus;
  to: IncidentStatus;
  reason?: string | undefined;
}): TransitionResult {
  const { type, from, to } = input;
  if (from === to)
    return { ok: false, code: 'same_state', message: 'Incident is already in that state' };
  const edge = edgesFrom(type, from).find((e) => e.to === to);
  if (!edge)
    return {
      ok: false,
      code: 'not_allowed',
      message: `Transition ${from} → ${to} is not allowed for ${type} incidents`,
    };
  const deviation = Boolean(edge.requiresReason);
  if (edge.requiresReason && !(input.reason && input.reason.trim().length >= 10)) {
    return {
      ok: false,
      code: 'reason_required',
      message: 'A reason of at least 10 characters is required for this transition',
    };
  }
  return { ok: true, requiresPermission: edge.requiresPermission, deviation };
}

export function allowedNextStates(type: IncidentType, from: IncidentStatus): IncidentStatus[] {
  return edgesFrom(type, from).map((e) => e.to);
}
