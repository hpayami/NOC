import type { IncidentStatus, Severity } from '@noc/shared';
import type { MessageKey } from '@/i18n/messages';

export const SEV_STYLE: Record<Severity, string> = {
  info: 'text-sev-info',
  low: 'text-sev-low',
  medium: 'text-sev-medium',
  high: 'text-sev-high',
  critical: 'text-sev-critical',
};

export const STATUS_LABEL: Record<IncidentStatus, MessageKey> = {
  new: 'inc.status.new',
  triage: 'inc.status.triage',
  investigation: 'inc.status.investigation',
  containment: 'inc.status.containment',
  eradication: 'inc.status.eradication',
  recovery: 'inc.status.recovery',
  closed: 'inc.status.closed',
};
