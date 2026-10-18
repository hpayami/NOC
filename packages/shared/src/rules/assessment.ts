import type { EngagementStatus, Severity } from '../enums';

/**
 * Engagement lifecycle. Draft → pending_approval → approved → active → completed. A scope change
 * on an approved/active engagement sends it back to pending_approval (handled by the service);
 * expiry comes from the authorisation window, never from a person.
 */
const EDGES: Record<EngagementStatus, readonly EngagementStatus[]> = {
  draft: ['pending_approval', 'cancelled'],
  pending_approval: ['approved', 'draft', 'cancelled'],
  approved: ['active', 'pending_approval', 'cancelled', 'expired'],
  active: ['paused', 'completed', 'cancelled', 'expired', 'pending_approval'],
  paused: ['active', 'completed', 'cancelled', 'expired'],
  completed: [],
  cancelled: [],
  expired: [],
};

export type EngagementTransition =
  { ok: true; requiresReason: boolean } | { ok: false; message: string };

export function validateEngagementTransition(
  from: EngagementStatus,
  to: EngagementStatus,
  reason?: string,
): EngagementTransition {
  if (from === to) return { ok: false, message: `Engagement is already ${from}` };
  if (!EDGES[from].includes(to))
    return { ok: false, message: `Transition ${from} → ${to} is not allowed` };
  const requiresReason = to === 'cancelled' || to === 'paused' || to === 'completed';
  if (requiresReason && !(reason && reason.trim().length >= 10))
    return { ok: false, message: `A reason of at least 10 characters is required to ${to}` };
  return { ok: true, requiresReason };
}

/** Services whose mere exposure on an internal network is a finding worth tracking. */
export const RISKY_SERVICES: ReadonlyArray<{
  port: number;
  service: string;
  severity: Severity;
  cwe: string | null;
  why: string;
}> = [
  { port: 21, service: 'FTP', severity: 'medium', cwe: 'CWE-319', why: 'cleartext credentials' },
  {
    port: 23,
    service: 'Telnet',
    severity: 'high',
    cwe: 'CWE-319',
    why: 'cleartext administration',
  },
  { port: 139, service: 'NetBIOS', severity: 'low', cwe: null, why: 'legacy file-sharing surface' },
  { port: 445, service: 'SMB', severity: 'medium', cwe: null, why: 'lateral-movement surface' },
  {
    port: 1433,
    service: 'MSSQL',
    severity: 'medium',
    cwe: 'CWE-284',
    why: 'database reachable from network',
  },
  {
    port: 3306,
    service: 'MySQL',
    severity: 'medium',
    cwe: 'CWE-284',
    why: 'database reachable from network',
  },
  {
    port: 3389,
    service: 'RDP',
    severity: 'medium',
    cwe: null,
    why: 'remote administration surface',
  },
  {
    port: 5432,
    service: 'PostgreSQL',
    severity: 'medium',
    cwe: 'CWE-284',
    why: 'database reachable from network',
  },
  {
    port: 5900,
    service: 'VNC',
    severity: 'high',
    cwe: 'CWE-319',
    why: 'remote desktop, often unauthenticated',
  },
  {
    port: 6379,
    service: 'Redis',
    severity: 'high',
    cwe: 'CWE-306',
    why: 'typically unauthenticated',
  },
  {
    port: 9200,
    service: 'Elasticsearch',
    severity: 'high',
    cwe: 'CWE-306',
    why: 'typically unauthenticated',
  },
  {
    port: 11211,
    service: 'Memcached',
    severity: 'high',
    cwe: 'CWE-306',
    why: 'unauthenticated; amplification',
  },
  {
    port: 27017,
    service: 'MongoDB',
    severity: 'high',
    cwe: 'CWE-306',
    why: 'typically unauthenticated',
  },
];

/** An exposed-service finding for an open port, or null when the port is not in the risky set. */
export function findingForOpenPort(
  port: number,
): { title: string; severity: Severity; cwe: string[]; description: string } | null {
  const r = RISKY_SERVICES.find((s) => s.port === port);
  if (!r) return null;
  return {
    title: `Exposed ${r.service} service on tcp/${r.port}`,
    severity: r.severity,
    cwe: r.cwe ? [r.cwe] : [],
    description: `A TCP connection to port ${r.port} (${r.service}) succeeded from the assessment worker: ${r.why}. Exposure was observed, not exploited; verify whether the service is intended to be reachable from this network position and whether it requires authentication.`,
  };
}
