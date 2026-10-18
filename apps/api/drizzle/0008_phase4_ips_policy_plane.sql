CREATE TYPE "public"."ips_apply_state" AS ENUM('none', 'pending', 'applied', 'failed');--> statement-breakpoint
CREATE TYPE "public"."ips_policy_action" AS ENUM('drop', 'reject');--> statement-breakpoint
CREATE TYPE "public"."ips_policy_mode" AS ENUM('ids', 'ips_test', 'ips');--> statement-breakpoint
CREATE TYPE "public"."ips_policy_status" AS ENUM('pending_approval', 'approved', 'enabled', 'disabled', 'rejected', 'expired');--> statement-breakpoint
CREATE TABLE "ips_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"sensor_id" uuid NOT NULL,
	"mode" "ips_policy_mode" NOT NULL,
	"action" "ips_policy_action" DEFAULT 'drop' NOT NULL,
	"protected_cidrs" "cidr"[] DEFAULT '{}' NOT NULL,
	"excluded_cidrs" "cidr"[] DEFAULT '{}' NOT NULL,
	"rule_ids" uuid[] DEFAULT '{}' NOT NULL,
	"status" "ips_policy_status" DEFAULT 'pending_approval' NOT NULL,
	"version" integer DEFAULT 0 NOT NULL,
	"justification" text DEFAULT '' NOT NULL,
	"rollback_plan" text DEFAULT '' NOT NULL,
	"proposed_by" uuid NOT NULL,
	"required_approvals" integer DEFAULT 2 NOT NULL,
	"enabled_by" uuid,
	"enabled_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"disabled_by" uuid,
	"disabled_at" timestamp with time zone,
	"disable_reason" text,
	"apply_state" "ips_apply_state" DEFAULT 'none' NOT NULL,
	"applied_version" integer,
	"applied_at" timestamp with time zone,
	"apply_detail" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "sensors" ADD COLUMN "inline_capable" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "ips_policies" ADD CONSTRAINT "ips_policies_sensor_id_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ips_policies" ADD CONSTRAINT "ips_policies_proposed_by_users_id_fk" FOREIGN KEY ("proposed_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ips_policies" ADD CONSTRAINT "ips_policies_enabled_by_users_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ips_policies" ADD CONSTRAINT "ips_policies_disabled_by_users_id_fk" FOREIGN KEY ("disabled_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ips_policies_sensor_status_idx" ON "ips_policies" USING btree ("sensor_id","status");--> statement-breakpoint
CREATE INDEX "ips_policies_status_expires_idx" ON "ips_policies" USING btree ("status","expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "ips_policies_one_enabled_per_sensor_idx" ON "ips_policies" USING btree ("sensor_id") WHERE status = 'enabled';