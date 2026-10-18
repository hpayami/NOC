import { z } from 'zod';

/** Helper: declare a const tuple once and derive both the Zod enum and the TS union from it. */
const e = <T extends readonly [string, ...string[]]>(values: T) => z.enum(values);

export const SeverityValues = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const Severity = e(SeverityValues);
export type Severity = z.infer<typeof Severity>;

/** Confidence in a detection is tracked separately from severity and from investigation status. */
export const ConfidenceValues = ['unknown', 'low', 'medium', 'high'] as const;
export const Confidence = e(ConfidenceValues);
export type Confidence = z.infer<typeof Confidence>;

export const CriticalityValues = ['unclassified', 'low', 'medium', 'high', 'critical'] as const;
export const Criticality = e(CriticalityValues);
export type Criticality = z.infer<typeof Criticality>;

export const AssetClassValues = [
  'server_physical',
  'server_virtual',
  'workstation',
  'laptop',
  'network_switch',
  'network_router',
  'firewall',
  'vpn_gateway',
  'wireless_ap',
  'wireless_controller',
  'load_balancer',
  'storage_appliance',
  'hypervisor',
  'virtual_appliance',
  'printer',
  'iot_device',
  'ot_device',
  'network_sensor',
  'security_appliance',
  'cloud_resource',
  'unknown',
] as const;
export const AssetClass = e(AssetClassValues);
export type AssetClass = z.infer<typeof AssetClass>;

export const OperationalStatusValues = [
  'online',
  'offline',
  'degraded',
  'unreachable_monitoring_path',
  'maintenance',
  'unknown',
] as const;
export const OperationalStatus = e(OperationalStatusValues);
export type OperationalStatus = z.infer<typeof OperationalStatus>;

/**
 * What the platform can honestly say about an asset's security posture.
 * "no_threat_detected" is only a valid output when the asset is monitored by a healthy sensor with
 * complete, fresh telemetry. Absence of alerts alone never implies "secure".
 */
export const AssuranceStateValues = [
  'no_threat_detected',
  'detection_unavailable',
  'asset_not_monitored',
  'telemetry_incomplete',
  'sensor_unhealthy',
  'assessment_not_performed',
  'assessment_with_findings',
] as const;
export const AssuranceState = e(AssuranceStateValues);
export type AssuranceState = z.infer<typeof AssuranceState>;

export const DiscoveryMethodValues = [
  'passive_observation',
  'arp_neighbor',
  'dhcp_lease',
  'dns',
  'snmpv3',
  'icmp',
  'tcp_service_check',
  'ssh_inventory',
  'winrm',
  'wmi',
  'endpoint_agent',
  'vendor_api',
  'hypervisor_api',
  'cloud_api',
  'cmdb_import',
  'manual',
] as const;
export const DiscoveryMethod = e(DiscoveryMethodValues);
export type DiscoveryMethod = z.infer<typeof DiscoveryMethod>;

/** How strongly a topology edge is supported. Observed traffic is never physical cabling. */
export const RelationshipVerificationValues = ['inferred', 'verified'] as const;
export const RelationshipVerification = e(RelationshipVerificationValues);
export type RelationshipVerification = z.infer<typeof RelationshipVerification>;

export const RelationshipKindValues = [
  'physical_link',
  'layer2_adjacency',
  'routed_path',
  'observed_communication',
  'service_dependency',
  'sensor_coverage',
  'hosted_on',
] as const;
export const RelationshipKind = e(RelationshipKindValues);
export type RelationshipKind = z.infer<typeof RelationshipKind>;

export const SensorKindValues = [
  'suricata',
  'zeek',
  'host_agent',
  'snmp_poller',
  'syslog_collector',
  'flow_collector',
  'other',
] as const;
export const SensorKind = e(SensorKindValues);
export type SensorKind = z.infer<typeof SensorKind>;

export const SensorModeValues = ['out_of_band', 'inline_prevention', 'collector_only'] as const;
export const SensorMode = e(SensorModeValues);
export type SensorMode = z.infer<typeof SensorMode>;

export const SensorHealthStateValues = [
  'healthy',
  'degraded',
  'unhealthy',
  'silent',
  'unknown',
] as const;
export const SensorHealthState = e(SensorHealthStateValues);
export type SensorHealthState = z.infer<typeof SensorHealthState>;

export const EventSourceProductValues = [
  'suricata',
  'zeek',
  'syslog',
  'snmp',
  'netflow',
  'endpoint_agent',
  'platform',
  'other',
] as const;
export const EventSourceProduct = e(EventSourceProductValues);
export type EventSourceProduct = z.infer<typeof EventSourceProduct>;

export const EventCategoryValues = [
  'network',
  'authentication',
  'host',
  'dns',
  'tls',
  'http',
  'file',
  'infrastructure',
  'detection',
  'audit',
  'other',
] as const;
export const EventCategory = e(EventCategoryValues);
export type EventCategory = z.infer<typeof EventCategory>;

export const AlertStatusValues = [
  'new',
  'acknowledged',
  'investigating',
  'escalated',
  'suppressed',
  'false_positive',
  'resolved',
] as const;
export const AlertStatus = e(AlertStatusValues);
export type AlertStatus = z.infer<typeof AlertStatus>;

export const IncidentStatusValues = [
  'new',
  'triage',
  'investigation',
  'containment',
  'eradication',
  'recovery',
  'closed',
] as const;
export const IncidentStatus = e(IncidentStatusValues);
export type IncidentStatus = z.infer<typeof IncidentStatus>;

export const IncidentTypeValues = ['security', 'noc_outage', 'policy_violation'] as const;
export const IncidentType = e(IncidentTypeValues);
export type IncidentType = z.infer<typeof IncidentType>;

export const FindingStatusValues = [
  'open',
  'accepted_risk',
  'mitigated',
  'remediation_verified',
  'false_positive',
] as const;
export const FindingStatus = e(FindingStatusValues);
export type FindingStatus = z.infer<typeof FindingStatus>;

export const EngagementStatusValues = [
  'draft',
  'pending_approval',
  'approved',
  'active',
  'paused',
  'completed',
  'cancelled',
  'expired',
] as const;
export const EngagementStatus = e(EngagementStatusValues);
export type EngagementStatus = z.infer<typeof EngagementStatus>;

/** Non-destructive assessment techniques only. Destructive techniques are intentionally absent. */
export const AssessmentTechniqueValues = [
  'passive_discovery',
  'host_discovery',
  'service_fingerprint',
  'vulnerability_scan',
  'tls_assessment',
  'config_audit',
  'web_scan',
  'dependency_scan',
  'detection_validation',
] as const;
export const AssessmentTechnique = e(AssessmentTechniqueValues);
export type AssessmentTechnique = z.infer<typeof AssessmentTechnique>;

export const ResponseActionKindValues = [
  'recommend_isolation',
  'isolate_endpoint',
  'block_indicator',
  'disable_session',
  'collect_evidence',
  'update_detection_rule',
  'enable_inline_prevention',
  'escalate',
] as const;
export const ResponseActionKind = e(ResponseActionKindValues);
export type ResponseActionKind = z.infer<typeof ResponseActionKind>;

export const ResponseActionStatusValues = [
  'recommended',
  'pending_approval',
  'approved',
  'rejected',
  'executing',
  'executed',
  'verification_failed',
  'rolled_back',
  'expired',
  'failed',
] as const;
export const ResponseActionStatus = e(ResponseActionStatusValues);
export type ResponseActionStatus = z.infer<typeof ResponseActionStatus>;

export const ApprovalDecisionValues = ['approved', 'rejected'] as const;
export const ApprovalDecision = e(ApprovalDecisionValues);
export type ApprovalDecision = z.infer<typeof ApprovalDecision>;

export const UserStatusValues = ['active', 'disabled', 'locked'] as const;
export const UserStatus = e(UserStatusValues);
export type UserStatus = z.infer<typeof UserStatus>;

export const RuleSourceValues = ['et_open', 'custom', 'vendor', 'zeek_script', 'sigma'] as const;
export const RuleSource = e(RuleSourceValues);
export type RuleSource = z.infer<typeof RuleSource>;

export const RuleLifecycleValues = [
  'draft',
  'validated',
  'deployed',
  'disabled',
  'retired',
] as const;
export const RuleLifecycle = e(RuleLifecycleValues);
export type RuleLifecycle = z.infer<typeof RuleLifecycle>;

export const IndicatorKindValues = [
  'ipv4',
  'ipv6',
  'domain',
  'url',
  'sha256',
  'ja3',
  'email',
] as const;
export const IndicatorKind = e(IndicatorKindValues);
export type IndicatorKind = z.infer<typeof IndicatorKind>;

export const RemediationStatusValues = [
  'open',
  'in_progress',
  'awaiting_verification',
  'verified',
  'wont_fix',
] as const;
export const RemediationStatus = e(RemediationStatusValues);
export type RemediationStatus = z.infer<typeof RemediationStatus>;

export const CheckKindValues = ['tcp', 'http', 'icmp'] as const;
export const CheckKind = e(CheckKindValues);
export type CheckKind = z.infer<typeof CheckKind>;

export const CheckOutcomeValues = ['up', 'down', 'timeout', 'error', 'unsupported'] as const;
export const CheckOutcome = e(CheckOutcomeValues);
export type CheckOutcome = z.infer<typeof CheckOutcome>;

export const DiscoveryJobStatusValues = [
  'pending_approval',
  'approved',
  'rejected',
  'running',
  'completed',
  'cancelled',
  'failed',
] as const;
export const DiscoveryJobStatus = e(DiscoveryJobStatusValues);
export type DiscoveryJobStatus = z.infer<typeof DiscoveryJobStatus>;

export const CoverageStateValues = ['monitored', 'partial', 'unmonitored', 'unknown'] as const;
export const CoverageState = e(CoverageStateValues);
export type CoverageState = z.infer<typeof CoverageState>;
