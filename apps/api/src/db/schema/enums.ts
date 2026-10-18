import { pgEnum } from 'drizzle-orm/pg-core';
import {
  AlertStatusValues,
  CheckKindValues,
  CheckOutcomeValues,
  DiscoveryJobStatusValues,
  AssetClassValues,
  AssuranceStateValues,
  ConfidenceValues,
  CoverageStateValues,
  CriticalityValues,
  DiscoveryMethodValues,
  EngagementStatusValues,
  EventCategoryValues,
  EventSourceProductValues,
  FindingStatusValues,
  IncidentStatusValues,
  IncidentTypeValues,
  OperationalStatusValues,
  RelationshipKindValues,
  RelationshipVerificationValues,
  ResponseActionKindValues,
  ResponseActionStatusValues,
  RuleLifecycleValues,
  RuleSourceValues,
  SensorHealthStateValues,
  SensorKindValues,
  SensorModeValues,
  SeverityValues,
  UserStatusValues,
} from '@noc/shared';

// Postgres enums mirror the shared Zod enums so the database and the API contract cannot drift.
export const severityEnum = pgEnum('severity', SeverityValues);
export const confidenceEnum = pgEnum('confidence', ConfidenceValues);
export const criticalityEnum = pgEnum('criticality', CriticalityValues);
export const assetClassEnum = pgEnum('asset_class', AssetClassValues);
export const operationalStatusEnum = pgEnum('operational_status', OperationalStatusValues);
export const assuranceStateEnum = pgEnum('assurance_state', AssuranceStateValues);
export const discoveryMethodEnum = pgEnum('discovery_method', DiscoveryMethodValues);
export const relationshipVerificationEnum = pgEnum(
  'relationship_verification',
  RelationshipVerificationValues,
);
export const relationshipKindEnum = pgEnum('relationship_kind', RelationshipKindValues);
export const sensorKindEnum = pgEnum('sensor_kind', SensorKindValues);
export const sensorModeEnum = pgEnum('sensor_mode', SensorModeValues);
export const sensorHealthStateEnum = pgEnum('sensor_health_state', SensorHealthStateValues);
export const eventSourceProductEnum = pgEnum('event_source_product', EventSourceProductValues);
export const eventCategoryEnum = pgEnum('event_category', EventCategoryValues);
export const alertStatusEnum = pgEnum('alert_status', AlertStatusValues);
export const incidentStatusEnum = pgEnum('incident_status', IncidentStatusValues);
export const incidentTypeEnum = pgEnum('incident_type', IncidentTypeValues);
export const findingStatusEnum = pgEnum('finding_status', FindingStatusValues);
export const engagementStatusEnum = pgEnum('engagement_status', EngagementStatusValues);
export const responseActionKindEnum = pgEnum('response_action_kind', ResponseActionKindValues);
export const responseActionStatusEnum = pgEnum(
  'response_action_status',
  ResponseActionStatusValues,
);
export const userStatusEnum = pgEnum('user_status', UserStatusValues);
export const ruleSourceEnum = pgEnum('rule_source', RuleSourceValues);
export const ruleLifecycleEnum = pgEnum('rule_lifecycle', RuleLifecycleValues);
export const coverageStateEnum = pgEnum('coverage_state', CoverageStateValues);
export const checkKindEnum = pgEnum('check_kind', CheckKindValues);
export const checkOutcomeEnum = pgEnum('check_outcome', CheckOutcomeValues);
export const discoveryJobStatusEnum = pgEnum('discovery_job_status', DiscoveryJobStatusValues);
export const auditOutcomeEnum = pgEnum('audit_outcome', ['success', 'denied', 'failure']);
export const approvalSubjectEnum = pgEnum('approval_subject', [
  'response_action',
  'assessment_engagement',
  'detection_rule_deployment',
  'ips_policy',
]);
export const approvalDecisionEnum = pgEnum('approval_decision', ['approved', 'rejected']);
export const retentionDataClassEnum = pgEnum('retention_data_class', [
  'security_events',
  'raw_events',
  'flows',
  'audit',
  'evidence',
  'metrics',
  'observations',
  'pcap',
]);
