import type { Permission } from '@noc/shared';
import type { MessageKey } from '@/i18n/messages';

export interface NavItem {
  slug: string;
  label: MessageKey;
  /** Capability ids from /api/v1/platform/status this workspace depends on. */
  capabilities: string[];
  /** Permission needed to see the item at all; the API enforces the same on every call. */
  permission: Permission;
  phase: number;
  implemented: boolean;
}

/** The 19 required workspaces, in navigation order. Only `implemented` ones have real pages. */
export const NAV: NavItem[] = [
  {
    slug: 'command-center',
    label: 'nav.command_center',
    capabilities: [],
    permission: 'platform.status.read',
    phase: 0,
    implemented: true,
  },
  {
    slug: 'assets',
    label: 'nav.assets',
    capabilities: ['asset.inventory', 'asset.discovery.passive', 'asset.discovery.active'],
    permission: 'assets.read',
    phase: 1,
    implemented: true,
  },
  {
    slug: 'topology',
    label: 'nav.topology',
    capabilities: ['network.topology'],
    permission: 'network.read',
    phase: 1,
    implemented: true,
  },
  {
    slug: 'nids',
    label: 'nav.nids',
    capabilities: ['nids.suricata', 'nsm.zeek', 'events.pipeline'],
    permission: 'events.read',
    phase: 2,
    implemented: true,
  },
  {
    slug: 'nips',
    label: 'nav.nips',
    capabilities: ['nips.inline_prevention', 'nips.policy_plane'],
    permission: 'ips.read',
    phase: 4,
    implemented: true,
  },
  {
    slug: 'noc',
    label: 'nav.noc',
    capabilities: ['noc.health_monitoring'],
    permission: 'monitoring.read',
    phase: 1,
    implemented: true,
  },
  {
    slug: 'soc-alerts',
    label: 'nav.soc_alerts',
    capabilities: ['soc.alerts'],
    permission: 'alerts.read',
    phase: 2,
    implemented: true,
  },
  {
    slug: 'incidents',
    label: 'nav.incidents',
    capabilities: ['soc.incidents', 'response.actions'],
    permission: 'incidents.read',
    phase: 3,
    implemented: true,
  },
  {
    slug: 'blue-team',
    label: 'nav.blue_team',
    capabilities: ['detection.rule_registry', 'nids.suricata', 'events.pipeline'],
    permission: 'detection_rules.read',
    phase: 3,
    implemented: true,
  },
  {
    slug: 'red-team',
    label: 'nav.red_team',
    capabilities: ['assessment.engagements'],
    permission: 'assessments.read',
    phase: 5,
    implemented: true,
  },
  {
    slug: 'pentest',
    label: 'nav.pentest',
    capabilities: ['assessment.engagements', 'assessment.workers'],
    permission: 'assessments.read',
    phase: 5,
    implemented: true,
  },
  {
    slug: 'vulnerabilities',
    label: 'nav.vulns',
    capabilities: ['assessment.engagements'],
    permission: 'findings.read',
    phase: 5,
    implemented: true,
  },
  {
    slug: 'threat-intel',
    label: 'nav.threat_intel',
    capabilities: ['threat_intel.indicators', 'events.pipeline'],
    permission: 'threat_intel.read',
    phase: 3,
    implemented: true,
  },
  {
    slug: 'detection-engineering',
    label: 'nav.detection_eng',
    capabilities: ['nids.suricata'],
    permission: 'detection_rules.read',
    phase: 2,
    implemented: true,
  },
  {
    slug: 'ml-analytics',
    label: 'nav.ml',
    capabilities: ['ml.analytics'],
    permission: 'ml.read',
    phase: 6,
    implemented: true,
  },
  {
    slug: 'sensors',
    label: 'nav.sensors',
    capabilities: ['nids.suricata', 'nsm.zeek'],
    permission: 'sensors.read',
    phase: 1,
    implemented: true,
  },
  {
    slug: 'audit-logs',
    label: 'nav.audit',
    capabilities: ['audit.tamper_evident'],
    permission: 'audit.read',
    phase: 0,
    implemented: true,
  },
  {
    slug: 'reports',
    label: 'nav.reports',
    capabilities: ['soc.incidents', 'assessment.engagements'],
    permission: 'platform.status.read',
    phase: 5,
    implemented: true,
  },
  {
    slug: 'administration',
    label: 'nav.admin',
    capabilities: ['auth.rbac'],
    permission: 'users.read',
    phase: 0,
    implemented: true,
  },
];

export const navBySlug = (slug: string) => NAV.find((n) => n.slug === slug);
