CREATE TYPE "public"."check_kind" AS ENUM('tcp', 'http', 'icmp');--> statement-breakpoint
CREATE TYPE "public"."check_outcome" AS ENUM('up', 'down', 'timeout', 'error', 'unsupported');--> statement-breakpoint
CREATE TABLE "asset_metrics" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"asset_id" uuid NOT NULL,
	"metric" text NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"value" double precision NOT NULL,
	"unit" text,
	"source" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "check_results" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"check_id" uuid NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"outcome" "check_outcome" NOT NULL,
	"latency_ms" integer,
	"detail" text,
	"collector_state" text DEFAULT 'platform' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "maintenance_windows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid,
	"segment_id" uuid,
	"starts_at" timestamp with time zone NOT NULL,
	"ends_at" timestamp with time zone NOT NULL,
	"reason" text DEFAULT '' NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monitoring_checks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"kind" "check_kind" NOT NULL,
	"target" "inet" NOT NULL,
	"port" integer,
	"interval_seconds" integer DEFAULT 60 NOT NULL,
	"timeout_ms" integer DEFAULT 2000 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"collector_id" uuid,
	"last_run_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "asset_metrics" ADD CONSTRAINT "asset_metrics_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "check_results" ADD CONSTRAINT "check_results_check_id_monitoring_checks_id_fk" FOREIGN KEY ("check_id") REFERENCES "public"."monitoring_checks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "maintenance_windows" ADD CONSTRAINT "maintenance_windows_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "maintenance_windows" ADD CONSTRAINT "maintenance_windows_segment_id_network_segments_id_fk" FOREIGN KEY ("segment_id") REFERENCES "public"."network_segments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitoring_checks" ADD CONSTRAINT "monitoring_checks_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitoring_checks" ADD CONSTRAINT "monitoring_checks_collector_id_sensors_id_fk" FOREIGN KEY ("collector_id") REFERENCES "public"."sensors"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "asset_metrics_asset_metric_time_idx" ON "asset_metrics" USING btree ("asset_id","metric","observed_at");--> statement-breakpoint
CREATE INDEX "check_results_check_time_idx" ON "check_results" USING btree ("check_id","observed_at");--> statement-breakpoint
CREATE INDEX "maintenance_windows_range_idx" ON "maintenance_windows" USING btree ("starts_at","ends_at");--> statement-breakpoint
CREATE INDEX "maintenance_windows_asset_idx" ON "maintenance_windows" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "maintenance_windows_segment_idx" ON "maintenance_windows" USING btree ("segment_id");--> statement-breakpoint
CREATE INDEX "monitoring_checks_due_idx" ON "monitoring_checks" USING btree ("enabled","collector_id","last_run_at");--> statement-breakpoint
CREATE INDEX "monitoring_checks_asset_idx" ON "monitoring_checks" USING btree ("asset_id");