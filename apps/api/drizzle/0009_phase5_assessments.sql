CREATE TYPE "public"."assessment_run_status" AS ENUM('queued', 'running', 'completed', 'cancelled', 'failed');--> statement-breakpoint
CREATE TYPE "public"."assessment_technique" AS ENUM('passive_discovery', 'host_discovery', 'service_fingerprint', 'vulnerability_scan', 'tls_assessment', 'config_audit', 'web_scan', 'dependency_scan', 'detection_validation');--> statement-breakpoint
CREATE TABLE "assessment_run_targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"run_id" uuid NOT NULL,
	"target" "inet" NOT NULL,
	"decision" text DEFAULT 'pending' NOT NULL,
	"reasons" text[] DEFAULT '{}' NOT NULL,
	"outcome" text DEFAULT 'pending' NOT NULL,
	"open_ports" integer[] DEFAULT '{}' NOT NULL,
	"observed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "assessment_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"scope_version" integer NOT NULL,
	"technique" "assessment_technique" NOT NULL,
	"status" "assessment_run_status" DEFAULT 'queued' NOT NULL,
	"dry_run" boolean DEFAULT true NOT NULL,
	"ports" integer[] DEFAULT '{}' NOT NULL,
	"requested_by" uuid NOT NULL,
	"note" text,
	"target_count" integer DEFAULT 0 NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"summary" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vulnerability_findings" ADD COLUMN "description" text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE "vulnerability_findings" ADD COLUMN "last_note" text;--> statement-breakpoint
ALTER TABLE "vulnerability_findings" ADD COLUMN "updated_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "approvals" ADD COLUMN "subject_version" integer;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "objective" text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "created_by" uuid;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "scope_version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "approved_scope_version" integer;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "activated_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "completed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD COLUMN "close_reason" text;--> statement-breakpoint
ALTER TABLE "assessment_run_targets" ADD CONSTRAINT "assessment_run_targets_run_id_assessment_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."assessment_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_runs" ADD CONSTRAINT "assessment_runs_engagement_id_assessment_engagements_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."assessment_engagements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_runs" ADD CONSTRAINT "assessment_runs_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "assessment_run_targets_run_idx" ON "assessment_run_targets" USING btree ("run_id");--> statement-breakpoint
CREATE INDEX "assessment_runs_engagement_created_idx" ON "assessment_runs" USING btree ("engagement_id","created_at");--> statement-breakpoint
ALTER TABLE "assessment_engagements" ADD CONSTRAINT "assessment_engagements_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "findings_asset_title_idx" ON "vulnerability_findings" USING btree ("asset_id","title");