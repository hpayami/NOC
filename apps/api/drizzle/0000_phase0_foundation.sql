CREATE TYPE "public"."alert_status" AS ENUM('new', 'acknowledged', 'investigating', 'escalated', 'suppressed', 'false_positive', 'resolved');--> statement-breakpoint
CREATE TYPE "public"."approval_decision" AS ENUM('approved', 'rejected');--> statement-breakpoint
CREATE TYPE "public"."approval_subject" AS ENUM('response_action', 'assessment_engagement', 'detection_rule_deployment', 'ips_policy');--> statement-breakpoint
CREATE TYPE "public"."asset_class" AS ENUM('server_physical', 'server_virtual', 'workstation', 'laptop', 'network_switch', 'network_router', 'firewall', 'vpn_gateway', 'wireless_ap', 'wireless_controller', 'load_balancer', 'storage_appliance', 'hypervisor', 'virtual_appliance', 'printer', 'iot_device', 'ot_device', 'network_sensor', 'security_appliance', 'cloud_resource', 'unknown');--> statement-breakpoint
CREATE TYPE "public"."assurance_state" AS ENUM('no_threat_detected', 'detection_unavailable', 'asset_not_monitored', 'telemetry_incomplete', 'sensor_unhealthy', 'assessment_not_performed', 'assessment_with_findings');--> statement-breakpoint
CREATE TYPE "public"."audit_outcome" AS ENUM('success', 'denied', 'failure');--> statement-breakpoint
CREATE TYPE "public"."confidence" AS ENUM('unknown', 'low', 'medium', 'high');--> statement-breakpoint
CREATE TYPE "public"."coverage_state" AS ENUM('monitored', 'partial', 'unmonitored', 'unknown');--> statement-breakpoint
CREATE TYPE "public"."criticality" AS ENUM('unclassified', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."discovery_method" AS ENUM('passive_observation', 'arp_neighbor', 'dhcp_lease', 'dns', 'snmpv3', 'icmp', 'tcp_service_check', 'ssh_inventory', 'winrm', 'wmi', 'endpoint_agent', 'vendor_api', 'hypervisor_api', 'cloud_api', 'cmdb_import', 'manual');--> statement-breakpoint
CREATE TYPE "public"."engagement_status" AS ENUM('draft', 'pending_approval', 'approved', 'active', 'paused', 'completed', 'cancelled', 'expired');--> statement-breakpoint
CREATE TYPE "public"."event_category" AS ENUM('network', 'authentication', 'host', 'dns', 'tls', 'http', 'file', 'infrastructure', 'detection', 'audit', 'other');--> statement-breakpoint
CREATE TYPE "public"."event_source_product" AS ENUM('suricata', 'zeek', 'syslog', 'snmp', 'netflow', 'endpoint_agent', 'platform', 'other');--> statement-breakpoint
CREATE TYPE "public"."finding_status" AS ENUM('open', 'accepted_risk', 'mitigated', 'remediation_verified', 'false_positive');--> statement-breakpoint
CREATE TYPE "public"."incident_status" AS ENUM('new', 'triage', 'investigation', 'containment', 'eradication', 'recovery', 'closed');--> statement-breakpoint
CREATE TYPE "public"."incident_type" AS ENUM('security', 'noc_outage', 'policy_violation');--> statement-breakpoint
CREATE TYPE "public"."operational_status" AS ENUM('online', 'offline', 'degraded', 'unreachable_monitoring_path', 'maintenance', 'unknown');--> statement-breakpoint
CREATE TYPE "public"."relationship_kind" AS ENUM('physical_link', 'layer2_adjacency', 'routed_path', 'observed_communication', 'service_dependency', 'sensor_coverage', 'hosted_on');--> statement-breakpoint
CREATE TYPE "public"."relationship_verification" AS ENUM('inferred', 'verified');--> statement-breakpoint
CREATE TYPE "public"."response_action_kind" AS ENUM('recommend_isolation', 'isolate_endpoint', 'block_indicator', 'disable_session', 'collect_evidence', 'update_detection_rule', 'enable_inline_prevention', 'escalate');--> statement-breakpoint
CREATE TYPE "public"."response_action_status" AS ENUM('recommended', 'pending_approval', 'approved', 'rejected', 'executing', 'executed', 'verification_failed', 'rolled_back', 'expired', 'failed');--> statement-breakpoint
CREATE TYPE "public"."retention_data_class" AS ENUM('security_events', 'raw_events', 'flows', 'audit', 'evidence', 'metrics', 'pcap');--> statement-breakpoint
CREATE TYPE "public"."rule_lifecycle" AS ENUM('draft', 'validated', 'deployed', 'disabled', 'retired');--> statement-breakpoint
CREATE TYPE "public"."rule_source" AS ENUM('et_open', 'custom', 'vendor', 'zeek_script', 'sigma');--> statement-breakpoint
CREATE TYPE "public"."sensor_health_state" AS ENUM('healthy', 'degraded', 'unhealthy', 'silent', 'unknown');--> statement-breakpoint
CREATE TYPE "public"."sensor_kind" AS ENUM('suricata', 'zeek', 'host_agent', 'snmp_poller', 'syslog_collector', 'flow_collector', 'other');--> statement-breakpoint
CREATE TYPE "public"."sensor_mode" AS ENUM('out_of_band', 'inline_prevention', 'collector_only');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('info', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."user_status" AS ENUM('active', 'disabled', 'locked');--> statement-breakpoint
CREATE TABLE "permissions" (
	"key" text PRIMARY KEY NOT NULL,
	"description" text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"family_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone,
	"replaced_by" uuid,
	"created_ip" "inet",
	"user_agent" text
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"role_key" text NOT NULL,
	"permission_key" text NOT NULL,
	CONSTRAINT "role_permissions_role_key_permission_key_pk" PRIMARY KEY("role_key","permission_key")
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"key" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"name_fa" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"builtin" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_roles" (
	"user_id" uuid NOT NULL,
	"role_key" text NOT NULL,
	"granted_by" uuid,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_roles_user_id_role_key_pk" PRIMARY KEY("user_id","role_key")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"display_name" text NOT NULL,
	"password_hash" text NOT NULL,
	"status" "user_status" DEFAULT 'active' NOT NULL,
	"token_version" integer DEFAULT 0 NOT NULL,
	"failed_login_count" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"mfa_enrolled" boolean DEFAULT false NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "asset_interfaces" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"name" text NOT NULL,
	"mac_address" "macaddr",
	"ip_addresses" "inet"[] DEFAULT '{}' NOT NULL,
	"speed_mbps" integer,
	"admin_state" text DEFAULT 'unknown' NOT NULL,
	"oper_state" text DEFAULT 'unknown' NOT NULL,
	"vlan_id" integer
);
--> statement-breakpoint
CREATE TABLE "asset_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid,
	"source" text NOT NULL,
	"method" "discovery_method" NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"mac_addresses" "macaddr"[] DEFAULT '{}' NOT NULL,
	"ip_addresses" "inet"[] DEFAULT '{}' NOT NULL,
	"hostnames" text[] DEFAULT '{}' NOT NULL,
	"cloud_instance_id" text,
	"agent_id" text,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"conflicts_with" uuid[] DEFAULT '{}' NOT NULL,
	"ingested_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"hostname" text,
	"asset_class" "asset_class" DEFAULT 'unknown' NOT NULL,
	"manufacturer" text,
	"model" text,
	"serial_number" text,
	"os_name" text,
	"os_version" text,
	"firmware_version" text,
	"cpu_architecture" text,
	"ram_mb" integer,
	"segment_id" uuid,
	"role" text,
	"criticality" "criticality" DEFAULT 'unclassified' NOT NULL,
	"owner" text,
	"responsible_team" text,
	"discovery_methods" "discovery_method"[] DEFAULT '{}' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"operational_status" "operational_status" DEFAULT 'unknown' NOT NULL,
	"monitoring_coverage" "coverage_state" DEFAULT 'unknown' NOT NULL,
	"credentialed_assessment_status" text DEFAULT 'not_performed' NOT NULL,
	"assurance_state" "assurance_state" DEFAULT 'asset_not_monitored' NOT NULL,
	"data_confidence" real DEFAULT 0 NOT NULL,
	"provenance" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "network_segments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"site" text,
	"cidr" "cidr",
	"vlan_id" integer,
	"active_discovery_allowed" boolean DEFAULT false NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "topology_relationships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kind" "relationship_kind" NOT NULL,
	"source_asset_id" uuid NOT NULL,
	"target_asset_id" uuid NOT NULL,
	"source_interface_id" uuid,
	"target_interface_id" uuid,
	"verification" "relationship_verification" DEFAULT 'inferred' NOT NULL,
	"evidence" text DEFAULT '' NOT NULL,
	"first_observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_observed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sensor_health" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"sensor_id" uuid NOT NULL,
	"recorded_at" timestamp with time zone DEFAULT now() NOT NULL,
	"state" "sensor_health_state" NOT NULL,
	"heartbeat_age_seconds" integer,
	"event_lag_seconds" integer,
	"packets_captured" bigint,
	"packets_dropped" bigint,
	"cpu_percent" real,
	"memory_percent" real,
	"detail" text
);
--> statement-breakpoint
CREATE TABLE "sensors" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"kind" "sensor_kind" NOT NULL,
	"mode" "sensor_mode" DEFAULT 'out_of_band' NOT NULL,
	"host_asset_id" uuid,
	"site" text,
	"monitored_segment_ids" uuid[] DEFAULT '{}' NOT NULL,
	"engine_version" text,
	"rule_set_version" text,
	"enabled" boolean DEFAULT false NOT NULL,
	"credential_hash" text,
	"registered_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_heartbeat_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"title" text NOT NULL,
	"status" "alert_status" DEFAULT 'new' NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" "confidence" DEFAULT 'unknown' NOT NULL,
	"priority_score" real DEFAULT 0 NOT NULL,
	"rule_id" uuid,
	"source_product" "event_source_product" NOT NULL,
	"asset_id" uuid,
	"dedup_key" text NOT NULL,
	"occurrence_count" integer DEFAULT 1 NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"assignee_id" uuid,
	"incident_id" uuid,
	"suppressed_until" timestamp with time zone,
	"disposition_note" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "detection_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source" "rule_source" NOT NULL,
	"external_id" text NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"name" text NOT NULL,
	"lifecycle" "rule_lifecycle" DEFAULT 'draft' NOT NULL,
	"severity" "severity" DEFAULT 'medium' NOT NULL,
	"attack_techniques" text[] DEFAULT '{}' NOT NULL,
	"license" text,
	"content_sha256" text NOT NULL,
	"validated_at" timestamp with time zone,
	"deployed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incident_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"incident_id" uuid NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_id" uuid,
	"kind" text NOT NULL,
	"from_status" "incident_status",
	"to_status" "incident_status",
	"note" text,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"title" text NOT NULL,
	"type" "incident_type" DEFAULT 'security' NOT NULL,
	"status" "incident_status" DEFAULT 'new' NOT NULL,
	"severity" "severity" NOT NULL,
	"assignee_id" uuid,
	"commander_id" uuid,
	"summary" text DEFAULT '' NOT NULL,
	"opened_at" timestamp with time zone DEFAULT now() NOT NULL,
	"closed_at" timestamp with time zone,
	"closure_reason" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"schema_version" text NOT NULL,
	"event_time" timestamp with time zone NOT NULL,
	"ingest_time" timestamp with time zone DEFAULT now() NOT NULL,
	"source_product" "event_source_product" NOT NULL,
	"source_sensor_id" uuid,
	"category" "event_category" NOT NULL,
	"type" text NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" "confidence" DEFAULT 'unknown' NOT NULL,
	"src_asset_id" uuid,
	"dst_asset_id" uuid,
	"src_ip" "inet",
	"dst_ip" "inet",
	"src_port" integer,
	"dst_port" integer,
	"protocol" text,
	"rule_id" text,
	"threat_classification" text[] DEFAULT '{}' NOT NULL,
	"incident_id" uuid,
	"correlation_ids" text[] DEFAULT '{}' NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"original_ref" jsonb,
	"engine" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"dedup_hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerability_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"engagement_id" uuid,
	"title" text NOT NULL,
	"status" "finding_status" DEFAULT 'open' NOT NULL,
	"severity" "severity" NOT NULL,
	"cve" text[] DEFAULT '{}' NOT NULL,
	"cwe" text[] DEFAULT '{}' NOT NULL,
	"cvss_base_score" real,
	"cvss_vector" text,
	"validated" boolean DEFAULT false NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_detected_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_detected_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "approvals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subject_type" "approval_subject" NOT NULL,
	"subject_id" uuid NOT NULL,
	"approver_id" uuid NOT NULL,
	"decision" "approval_decision" NOT NULL,
	"justification" text DEFAULT '' NOT NULL,
	"decided_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assessment_engagements" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"reference" text NOT NULL,
	"authorizing_organization" text NOT NULL,
	"responsible_operator_id" uuid NOT NULL,
	"authorization_reference" text NOT NULL,
	"status" "engagement_status" DEFAULT 'draft' NOT NULL,
	"data_handling_restrictions" text DEFAULT '' NOT NULL,
	"stop_conditions" text[] DEFAULT '{}' NOT NULL,
	"emergency_contact" text NOT NULL,
	"evidence_retention_days" integer DEFAULT 365 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assessment_scopes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"include_cidrs" "cidr"[] DEFAULT '{}' NOT NULL,
	"include_addresses" "inet"[] DEFAULT '{}' NOT NULL,
	"exclude_cidrs" "cidr"[] DEFAULT '{}' NOT NULL,
	"exclude_addresses" "inet"[] DEFAULT '{}' NOT NULL,
	"allow_public_addresses" boolean DEFAULT false NOT NULL,
	"allowed_techniques" text[] DEFAULT '{}' NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"max_concurrency" integer DEFAULT 1 NOT NULL,
	"max_requests_per_second" real DEFAULT 1 NOT NULL,
	"approved_by" uuid,
	"approved_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "response_actions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kind" "response_action_kind" NOT NULL,
	"status" "response_action_status" DEFAULT 'recommended' NOT NULL,
	"incident_id" uuid,
	"target_type" text NOT NULL,
	"target_ref" text NOT NULL,
	"triggering_evidence" text[] DEFAULT '{}' NOT NULL,
	"proposed_by" uuid NOT NULL,
	"required_approvals" integer DEFAULT 1 NOT NULL,
	"executed_by" uuid,
	"executed_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"rollback_plan" text DEFAULT '' NOT NULL,
	"rolled_back_at" timestamp with time zone,
	"verification_result" text DEFAULT 'not_run' NOT NULL,
	"result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "retention_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"data_class" "retention_data_class" NOT NULL,
	"retention_days" integer NOT NULL,
	"legal_hold" boolean DEFAULT false NOT NULL,
	"updated_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "retention_policies_data_class_unique" UNIQUE("data_class")
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"seq" bigserial PRIMARY KEY NOT NULL,
	"id" uuid DEFAULT gen_random_uuid() NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"actor_id" uuid,
	"actor_label" text NOT NULL,
	"action" text NOT NULL,
	"outcome" "audit_outcome" NOT NULL,
	"target_type" text,
	"target_id" text,
	"request_id" text,
	"source_ip" "inet",
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"prev_hash" char(64) NOT NULL,
	"hash" char(64) NOT NULL
);
--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_key_roles_key_fk" FOREIGN KEY ("role_key") REFERENCES "public"."roles"("key") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permission_key_permissions_key_fk" FOREIGN KEY ("permission_key") REFERENCES "public"."permissions"("key") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_key_roles_key_fk" FOREIGN KEY ("role_key") REFERENCES "public"."roles"("key") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_interfaces" ADD CONSTRAINT "asset_interfaces_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_observations" ADD CONSTRAINT "asset_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_segment_id_network_segments_id_fk" FOREIGN KEY ("segment_id") REFERENCES "public"."network_segments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "topology_relationships" ADD CONSTRAINT "topology_relationships_source_asset_id_assets_id_fk" FOREIGN KEY ("source_asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "topology_relationships" ADD CONSTRAINT "topology_relationships_target_asset_id_assets_id_fk" FOREIGN KEY ("target_asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "topology_relationships" ADD CONSTRAINT "topology_relationships_source_interface_id_asset_interfaces_id_fk" FOREIGN KEY ("source_interface_id") REFERENCES "public"."asset_interfaces"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "topology_relationships" ADD CONSTRAINT "topology_relationships_target_interface_id_asset_interfaces_id_fk" FOREIGN KEY ("target_interface_id") REFERENCES "public"."asset_interfaces"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensor_health" ADD CONSTRAINT "sensor_health_sensor_id_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensors" ADD CONSTRAINT "sensors_host_asset_id_assets_id_fk" FOREIGN KEY ("host_asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_rule_id_detection_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."detection_rules"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_assignee_id_users_id_fk" FOREIGN KEY ("assignee_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_actor_id_users_id_fk" FOREIGN KEY ("actor_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_assignee_id_users_id_fk" FOREIGN KEY ("assignee_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_commander_id_users_id_fk" FOREIGN KEY ("commander_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_source_sensor_id_sensors_id_fk" FOREIGN KEY ("source_sensor_id") REFERENCES "public"."sensors"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_src_asset_id_assets_id_fk" FOREIGN KEY ("src_asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_dst_asset_id_assets_id_fk" FOREIGN KEY ("dst_asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_findings" ADD CONSTRAINT "vulnerability_findings_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approvals" ADD CONSTRAINT "approvals_approver_id_users_id_fk" FOREIGN KEY ("approver_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD CONSTRAINT "assessment_engagements_responsible_operator_id_users_id_fk" FOREIGN KEY ("responsible_operator_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_scopes" ADD CONSTRAINT "assessment_scopes_engagement_id_assessment_engagements_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."assessment_engagements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_scopes" ADD CONSTRAINT "assessment_scopes_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_proposed_by_users_id_fk" FOREIGN KEY ("proposed_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_executed_by_users_id_fk" FOREIGN KEY ("executed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "retention_policies" ADD CONSTRAINT "retention_policies_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "refresh_tokens_hash_idx" ON "refresh_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "refresh_tokens_family_idx" ON "refresh_tokens" USING btree ("family_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_user_expires_idx" ON "refresh_tokens" USING btree ("user_id","expires_at");--> statement-breakpoint
CREATE INDEX "role_permissions_permission_idx" ON "role_permissions" USING btree ("permission_key");--> statement-breakpoint
CREATE INDEX "user_roles_role_idx" ON "user_roles" USING btree ("role_key");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_lower_idx" ON "users" USING btree (lower("email"));--> statement-breakpoint
CREATE INDEX "users_status_idx" ON "users" USING btree ("status");--> statement-breakpoint
CREATE INDEX "asset_interfaces_asset_idx" ON "asset_interfaces" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "asset_interfaces_mac_idx" ON "asset_interfaces" USING btree ("mac_address");--> statement-breakpoint
CREATE INDEX "asset_interfaces_ips_gin_idx" ON "asset_interfaces" USING gin ("ip_addresses");--> statement-breakpoint
CREATE INDEX "asset_observations_asset_time_idx" ON "asset_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "asset_observations_time_idx" ON "asset_observations" USING btree ("observed_at");--> statement-breakpoint
CREATE INDEX "asset_observations_macs_gin_idx" ON "asset_observations" USING gin ("mac_addresses");--> statement-breakpoint
CREATE INDEX "asset_observations_ips_gin_idx" ON "asset_observations" USING gin ("ip_addresses");--> statement-breakpoint
CREATE INDEX "asset_observations_agent_idx" ON "asset_observations" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "asset_observations_cloud_idx" ON "asset_observations" USING btree ("cloud_instance_id");--> statement-breakpoint
CREATE INDEX "assets_last_seen_idx" ON "assets" USING btree ("last_seen_at");--> statement-breakpoint
CREATE INDEX "assets_segment_class_idx" ON "assets" USING btree ("segment_id","asset_class");--> statement-breakpoint
CREATE INDEX "assets_hostname_idx" ON "assets" USING btree ("hostname");--> statement-breakpoint
CREATE INDEX "assets_status_criticality_idx" ON "assets" USING btree ("operational_status","criticality");--> statement-breakpoint
CREATE INDEX "network_segments_site_idx" ON "network_segments" USING btree ("site");--> statement-breakpoint
CREATE INDEX "network_segments_cidr_idx" ON "network_segments" USING btree ("cidr");--> statement-breakpoint
CREATE INDEX "topology_source_idx" ON "topology_relationships" USING btree ("source_asset_id","kind");--> statement-breakpoint
CREATE INDEX "topology_target_idx" ON "topology_relationships" USING btree ("target_asset_id","kind");--> statement-breakpoint
CREATE INDEX "sensor_health_sensor_time_idx" ON "sensor_health" USING btree ("sensor_id","recorded_at");--> statement-breakpoint
CREATE INDEX "sensors_kind_enabled_idx" ON "sensors" USING btree ("kind","enabled");--> statement-breakpoint
CREATE INDEX "sensors_heartbeat_idx" ON "sensors" USING btree ("last_heartbeat_at");--> statement-breakpoint
CREATE INDEX "alerts_status_severity_last_seen_idx" ON "alerts" USING btree ("status","severity","last_seen_at");--> statement-breakpoint
CREATE INDEX "alerts_asset_status_idx" ON "alerts" USING btree ("asset_id","status");--> statement-breakpoint
CREATE INDEX "alerts_assignee_idx" ON "alerts" USING btree ("assignee_id");--> statement-breakpoint
CREATE INDEX "alerts_incident_idx" ON "alerts" USING btree ("incident_id");--> statement-breakpoint
CREATE UNIQUE INDEX "alerts_open_dedup_idx" ON "alerts" USING btree ("dedup_key") WHERE status not in ('resolved','false_positive');--> statement-breakpoint
CREATE UNIQUE INDEX "detection_rules_source_ext_rev_idx" ON "detection_rules" USING btree ("source","external_id","revision");--> statement-breakpoint
CREATE INDEX "detection_rules_lifecycle_idx" ON "detection_rules" USING btree ("lifecycle");--> statement-breakpoint
CREATE INDEX "incident_events_incident_time_idx" ON "incident_events" USING btree ("incident_id","occurred_at");--> statement-breakpoint
CREATE INDEX "incidents_status_severity_idx" ON "incidents" USING btree ("status","severity");--> statement-breakpoint
CREATE INDEX "incidents_assignee_status_idx" ON "incidents" USING btree ("assignee_id","status");--> statement-breakpoint
CREATE INDEX "incidents_opened_idx" ON "incidents" USING btree ("opened_at");--> statement-breakpoint
CREATE UNIQUE INDEX "security_events_dedup_idx" ON "security_events" USING btree ("dedup_hash");--> statement-breakpoint
CREATE INDEX "security_events_time_source_idx" ON "security_events" USING btree ("event_time","source_product");--> statement-breakpoint
CREATE INDEX "security_events_sensor_time_idx" ON "security_events" USING btree ("source_sensor_id","event_time");--> statement-breakpoint
CREATE INDEX "security_events_src_ip_time_idx" ON "security_events" USING btree ("src_ip","event_time");--> statement-breakpoint
CREATE INDEX "security_events_dst_ip_time_idx" ON "security_events" USING btree ("dst_ip","event_time");--> statement-breakpoint
CREATE INDEX "security_events_src_asset_time_idx" ON "security_events" USING btree ("src_asset_id","event_time");--> statement-breakpoint
CREATE INDEX "security_events_incident_idx" ON "security_events" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "findings_asset_status_idx" ON "vulnerability_findings" USING btree ("asset_id","status");--> statement-breakpoint
CREATE INDEX "findings_status_severity_idx" ON "vulnerability_findings" USING btree ("status","severity");--> statement-breakpoint
CREATE INDEX "findings_engagement_idx" ON "vulnerability_findings" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "approvals_subject_idx" ON "approvals" USING btree ("subject_type","subject_id");--> statement-breakpoint
CREATE INDEX "approvals_approver_idx" ON "approvals" USING btree ("approver_id");--> statement-breakpoint
CREATE INDEX "engagements_status_idx" ON "assessment_engagements" USING btree ("status");--> statement-breakpoint
CREATE INDEX "engagements_operator_idx" ON "assessment_engagements" USING btree ("responsible_operator_id");--> statement-breakpoint
CREATE INDEX "assessment_scopes_engagement_version_idx" ON "assessment_scopes" USING btree ("engagement_id","version");--> statement-breakpoint
CREATE INDEX "assessment_scopes_window_idx" ON "assessment_scopes" USING btree ("window_start","window_end");--> statement-breakpoint
CREATE INDEX "response_actions_status_idx" ON "response_actions" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "response_actions_incident_idx" ON "response_actions" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "response_actions_expires_idx" ON "response_actions" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_hash_idx" ON "audit_events" USING btree ("hash");--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_id_idx" ON "audit_events" USING btree ("id");--> statement-breakpoint
CREATE INDEX "audit_events_time_idx" ON "audit_events" USING btree ("occurred_at");--> statement-breakpoint
CREATE INDEX "audit_events_actor_time_idx" ON "audit_events" USING btree ("actor_id","occurred_at");--> statement-breakpoint
CREATE INDEX "audit_events_target_idx" ON "audit_events" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE INDEX "audit_events_action_idx" ON "audit_events" USING btree ("action");