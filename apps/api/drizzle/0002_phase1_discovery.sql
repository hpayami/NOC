CREATE TYPE "public"."discovery_job_status" AS ENUM('pending_approval', 'approved', 'rejected', 'running', 'completed', 'cancelled', 'failed');--> statement-breakpoint
CREATE TABLE "discovery_job_targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"job_id" uuid NOT NULL,
	"target" "inet" NOT NULL,
	"decision" text DEFAULT 'pending' NOT NULL,
	"reasons" text[] DEFAULT '{}' NOT NULL,
	"outcome" text DEFAULT 'pending' NOT NULL,
	"open_ports" integer[] DEFAULT '{}' NOT NULL,
	"observed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "discovery_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"status" "discovery_job_status" DEFAULT 'pending_approval' NOT NULL,
	"dry_run" boolean DEFAULT true NOT NULL,
	"scope" jsonb NOT NULL,
	"ports" integer[] DEFAULT '{}' NOT NULL,
	"requested_by" uuid NOT NULL,
	"approved_by" uuid,
	"approval_note" text,
	"target_count" integer DEFAULT 0 NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"summary" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "discovery_job_targets" ADD CONSTRAINT "discovery_job_targets_job_id_discovery_jobs_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."discovery_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_jobs" ADD CONSTRAINT "discovery_jobs_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_jobs" ADD CONSTRAINT "discovery_jobs_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "discovery_job_targets_job_idx" ON "discovery_job_targets" USING btree ("job_id","outcome");--> statement-breakpoint
CREATE INDEX "discovery_jobs_status_created_idx" ON "discovery_jobs" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "discovery_jobs_requester_idx" ON "discovery_jobs" USING btree ("requested_by");