import { z } from 'zod';

/**
 * Granular permission catalog. Roles are bundles of permissions; authorization checks are always
 * made against permissions, never against role names.
 */
export const PERMISSION_CATALOG = {
  'platform.status.read': 'View platform and capability status',
  'platform.metrics.read': 'Read operational metrics',
  'users.read': 'List users',
  'users.manage': 'Create, disable and unlock users',
  'users.assign_roles': 'Assign roles to other users',
  'roles.read': 'List roles and permissions',
  'assets.read': 'View asset inventory',
  'assets.read_sensitive': 'View serial numbers and other sensitive inventory fields',
  'assets.manage': 'Edit asset metadata and ownership',
  'discovery.run_passive': 'Run passive discovery within approved scope',
  'discovery.approve_active': 'Approve active discovery scope',
  'discovery.run_active': 'Run approved active discovery',
  'network.read': 'View network segments, topology and flows',
  'network.manage': 'Create and edit network segments',
  'sensors.read': 'View sensors and sensor health',
  'sensors.manage': 'Register and configure sensors',
  'monitoring.read': 'View availability checks, maintenance windows and metrics',
  'monitoring.manage': 'Create availability checks and maintenance windows',
  'monitoring.ingest': 'Report check results, heartbeats and metrics (collectors)',
  'events.read': 'Read normalized security events',
  'events.search': 'Run bounded threat-hunting queries',
  'events.ingest': 'Replay engine telemetry fixtures into a registered sensor (detection testing)',
  'alerts.read': 'View alerts',
  'alerts.triage': 'Acknowledge, assign, suppress and dispose alerts',
  'incidents.read': 'View incidents',
  'incidents.manage': 'Create and progress incidents',
  'incidents.close': 'Close incidents',
  'detection_rules.read': 'View detection rules',
  'detection_rules.change': 'Create and edit detection rules',
  'detection_rules.deploy': 'Deploy validated detection rules to sensors',
  'threat_intel.read': 'View threat intelligence',
  'threat_intel.manage': 'Manage threat intelligence sources and indicators',
  'findings.read': 'View vulnerability findings',
  'findings.manage': 'Triage findings and manage remediation tasks',
  'assessments.read': 'View assessment engagements',
  'assessments.plan': 'Draft assessment engagements and scopes',
  'assessments.approve': 'Approve assessment engagements and scopes',
  'assessments.execute': 'Execute approved assessments',
  'ips.read': 'View inline prevention policies',
  'ips.propose': 'Propose inline prevention policy changes',
  'ips.approve': 'Approve inline prevention policy changes',
  'ips.enable': 'Activate approved inline prevention policies',
  'response.read': 'View response actions',
  'response.propose': 'Propose response actions',
  'response.approve': 'Approve response actions',
  'response.execute': 'Execute approved response actions',
  'response.rollback': 'Roll back executed response actions',
  'evidence.read': 'View evidence',
  'evidence.export': 'Export evidence',
  'retention.read': 'View retention policies',
  'retention.modify': 'Modify retention policies',
  'audit.read': 'Read the audit trail',
  'audit.verify': 'Verify audit-trail integrity',
  'ml.read': 'View ML analytics',
  'ml.manage': 'Manage ML models',
} as const;

export type Permission = keyof typeof PERMISSION_CATALOG;
export const PERMISSIONS = Object.keys(PERMISSION_CATALOG) as Permission[];
export const PermissionSchema = z.enum(PERMISSIONS as [Permission, ...Permission[]]);

export const ROLE_KEYS = [
  'platform_admin',
  'security_admin',
  'noc_operator',
  'soc_analyst',
  'incident_responder',
  'blue_team_engineer',
  'red_team_operator',
  'vulnerability_analyst',
  'read_only_auditor',
] as const;
export type RoleKey = (typeof ROLE_KEYS)[number];
export const RoleKeySchema = z.enum(ROLE_KEYS);

interface RoleDefinition {
  name: string;
  nameFa: string;
  description: string;
  permissions: readonly Permission[];
}

const READ_BASE: Permission[] = ['platform.status.read'];

export const ROLE_DEFINITIONS: Record<RoleKey, RoleDefinition> = {
  platform_admin: {
    name: 'Platform Administrator',
    nameFa: 'مدیر پلتفرم',
    description:
      'Manages users, sensors and platform configuration. Cannot approve security-impacting changes.',
    permissions: [
      ...READ_BASE,
      'platform.metrics.read',
      'users.read',
      'users.manage',
      'users.assign_roles',
      'roles.read',
      'sensors.read',
      'sensors.manage',
      'monitoring.read',
      'monitoring.manage',
      'retention.read',
      'audit.read',
      'audit.verify',
      'assets.read',
      'network.read',
      'network.manage',
    ],
  },
  security_admin: {
    name: 'Security Administrator',
    nameFa: 'مدیر امنیت',
    description: 'Owns security policy and approvals. Approves but does not execute.',
    permissions: [
      ...READ_BASE,
      'roles.read',
      'assets.read',
      'assets.read_sensitive',
      'network.read',
      'sensors.read',
      'monitoring.read',
      'alerts.read',
      'incidents.read',
      'detection_rules.read',
      'detection_rules.deploy',
      'discovery.approve_active',
      'assessments.read',
      'assessments.approve',
      'ips.read',
      'ips.approve',
      'response.read',
      'response.approve',
      'retention.read',
      'retention.modify',
      'audit.read',
      'audit.verify',
      'findings.read',
    ],
  },
  noc_operator: {
    name: 'NOC Operator',
    nameFa: 'اپراتور NOC',
    description: 'Monitors infrastructure health and manages outage incidents.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'assets.manage',
      'discovery.run_passive',
      'network.read',
      'network.manage',
      'sensors.read',
      'monitoring.read',
      'monitoring.manage',
      'monitoring.ingest',
      'incidents.read',
      'incidents.manage',
      'alerts.read',
    ],
  },
  soc_analyst: {
    name: 'SOC Analyst',
    nameFa: 'تحلیلگر SOC',
    description: 'Triages alerts and investigates events.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'network.read',
      'sensors.read',
      'monitoring.read',
      'events.read',
      'events.search',
      'alerts.read',
      'alerts.triage',
      'incidents.read',
      'incidents.manage',
      'threat_intel.read',
      'detection_rules.read',
      'findings.read',
      'evidence.read',
      'response.read',
      'response.propose',
    ],
  },
  incident_responder: {
    name: 'Incident Responder',
    nameFa: 'پاسخ‌گوی حادثه',
    description: 'Leads incidents and executes approved response actions.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'network.read',
      'sensors.read',
      'events.read',
      'events.search',
      'alerts.read',
      'alerts.triage',
      'incidents.read',
      'incidents.manage',
      'incidents.close',
      'threat_intel.read',
      'evidence.read',
      'evidence.export',
      'response.read',
      'response.propose',
      'response.execute',
      'response.rollback',
    ],
  },
  blue_team_engineer: {
    name: 'Blue Team Engineer',
    nameFa: 'مهندس تیم آبی',
    description:
      'Engineers detections and proposes prevention policy; cannot deploy or approve alone.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'network.read',
      'sensors.read',
      'sensors.manage',
      'events.read',
      'events.search',
      'alerts.read',
      'detection_rules.read',
      'detection_rules.change',
      'threat_intel.read',
      'threat_intel.manage',
      'ips.read',
      'ips.propose',
      'ips.enable',
      'ml.read',
      'assessments.read',
      'response.read',
      'events.ingest',
    ],
  },
  red_team_operator: {
    name: 'Red Team Operator',
    nameFa: 'اپراتور تیم قرمز',
    description:
      'Plans and executes approved, in-scope assessments. Cannot approve own engagements.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'discovery.run_active',
      'assessments.read',
      'assessments.plan',
      'assessments.execute',
      'findings.read',
      'findings.manage',
      'evidence.read',
    ],
  },
  vulnerability_analyst: {
    name: 'Vulnerability Analyst',
    nameFa: 'تحلیلگر آسیب‌پذیری',
    description: 'Triages findings and tracks remediation.',
    permissions: [
      ...READ_BASE,
      'assets.read',
      'findings.read',
      'findings.manage',
      'assessments.read',
      'evidence.read',
    ],
  },
  read_only_auditor: {
    name: 'Read-Only Auditor',
    nameFa: 'ممیز فقط‌خواندنی',
    description: 'Read-only access to configuration, findings and the audit trail.',
    permissions: [
      ...READ_BASE,
      'roles.read',
      'users.read',
      'assets.read',
      'network.read',
      'sensors.read',
      'alerts.read',
      'incidents.read',
      'detection_rules.read',
      'findings.read',
      'assessments.read',
      'ips.read',
      'response.read',
      'retention.read',
      'monitoring.read',
      'audit.read',
      'audit.verify',
    ],
  },
};

/**
 * Separation-of-duties pairs. No single role may hold both permissions of a pair, so that the
 * party who approves a high-impact change is never the party who performs it.
 */
export const SEPARATED_PERMISSION_PAIRS: ReadonlyArray<readonly [Permission, Permission]> = [
  ['response.approve', 'response.execute'],
  ['assessments.approve', 'assessments.execute'],
  ['assessments.approve', 'assessments.plan'],
  ['ips.approve', 'ips.enable'],
  ['ips.approve', 'ips.propose'],
  ['detection_rules.change', 'detection_rules.deploy'],
  ['discovery.approve_active', 'discovery.run_active'],
];

export function permissionsForRoles(roleKeys: readonly RoleKey[]): Set<Permission> {
  const out = new Set<Permission>();
  for (const key of roleKeys) for (const p of ROLE_DEFINITIONS[key].permissions) out.add(p);
  return out;
}

export function hasPermission(held: ReadonlySet<Permission>, required: Permission): boolean {
  return held.has(required);
}
