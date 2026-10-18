CREATE TABLE "threat_indicator_matches" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"indicator_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"alert_id" uuid,
	"asset_id" uuid,
	"sensor_id" uuid,
	"matched_field" text NOT NULL,
	"matched_value" text NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_indicators" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"source" text NOT NULL,
	"confidence" integer DEFAULT 50 NOT NULL,
	"severity" "severity" DEFAULT 'medium' NOT NULL,
	"tags" text[] DEFAULT '{}' NOT NULL,
	"description" text,
	"expires_at" timestamp with time zone,
	"revoked" boolean DEFAULT false NOT NULL,
	"imported_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"match_count" integer DEFAULT 0 NOT NULL,
	"last_matched_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "threat_indicator_matches" ADD CONSTRAINT "threat_indicator_matches_indicator_id_threat_indicators_id_fk" FOREIGN KEY ("indicator_id") REFERENCES "public"."threat_indicators"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicator_matches" ADD CONSTRAINT "threat_indicator_matches_event_id_security_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."security_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicator_matches" ADD CONSTRAINT "threat_indicator_matches_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicator_matches" ADD CONSTRAINT "threat_indicator_matches_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicator_matches" ADD CONSTRAINT "threat_indicator_matches_sensor_id_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."sensors"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "threat_indicator_matches_unique_idx" ON "threat_indicator_matches" USING btree ("indicator_id","event_id","matched_field");--> statement-breakpoint
CREATE INDEX "threat_indicator_matches_observed_idx" ON "threat_indicator_matches" USING btree ("observed_at");--> statement-breakpoint
CREATE INDEX "threat_indicator_matches_asset_idx" ON "threat_indicator_matches" USING btree ("asset_id");--> statement-breakpoint
CREATE UNIQUE INDEX "threat_indicators_type_value_idx" ON "threat_indicators" USING btree ("type","value");--> statement-breakpoint
CREATE INDEX "threat_indicators_source_idx" ON "threat_indicators" USING btree ("source");--> statement-breakpoint
CREATE INDEX "threat_indicators_active_idx" ON "threat_indicators" USING btree ("revoked","expires_at");