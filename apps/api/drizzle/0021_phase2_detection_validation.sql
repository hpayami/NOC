CREATE TABLE "detection_validations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" uuid NOT NULL,
	"sensor_id" uuid NOT NULL,
	"sample_ref" text NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"expected_bundle_sha256" text,
	"reported_bundle_sha256" text,
	"expected_sids" integer[] DEFAULT '{}' NOT NULL,
	"fired_sids" integer[] DEFAULT '{}' NOT NULL,
	"missing_sids" integer[] DEFAULT '{}' NOT NULL,
	"unexpected_count" integer DEFAULT 0 NOT NULL,
	"verdict" text,
	"engine_version" text,
	"error" text,
	"duration_ms" integer,
	"note" text,
	"requested_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"dispatched_at" timestamp with time zone,
	"reported_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "detection_validations" ADD CONSTRAINT "detection_validations_rule_id_detection_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."detection_rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_validations" ADD CONSTRAINT "detection_validations_sensor_id_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_validations" ADD CONSTRAINT "detection_validations_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "detection_validations_sensor_status_idx" ON "detection_validations" USING btree ("sensor_id","status");--> statement-breakpoint
CREATE INDEX "detection_validations_rule_created_idx" ON "detection_validations" USING btree ("rule_id","created_at");