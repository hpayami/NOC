ALTER TABLE "sensors" ADD COLUMN "last_event_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "rule_ref" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "source_sensor_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "src_ip" "inet";--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "dst_ip" "inet";--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "last_event_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_source_sensor_id_sensors_id_fk" FOREIGN KEY ("source_sensor_id") REFERENCES "public"."sensors"("id") ON DELETE set null ON UPDATE no action;