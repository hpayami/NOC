CREATE TABLE "validation_schedules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" uuid NOT NULL,
	"sensor_id" uuid NOT NULL,
	"sample_ref" text NOT NULL,
	"interval_days" integer DEFAULT 7 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"note" text,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_queued_at" timestamp with time zone,
	"last_error" text
);
--> statement-breakpoint
ALTER TABLE "validation_schedules" ADD CONSTRAINT "validation_schedules_rule_id_detection_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."detection_rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "validation_schedules" ADD CONSTRAINT "validation_schedules_sensor_id_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "validation_schedules" ADD CONSTRAINT "validation_schedules_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "validation_schedules_pair_idx" ON "validation_schedules" USING btree ("rule_id","sensor_id");--> statement-breakpoint
CREATE INDEX "validation_schedules_enabled_idx" ON "validation_schedules" USING btree ("enabled");