CREATE TABLE "asset_services" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"proto" text NOT NULL,
	"port" integer NOT NULL,
	"address" "inet",
	"process" text,
	"source" text NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "sensors" ADD COLUMN "enrolment_token_hash" text;--> statement-breakpoint
ALTER TABLE "sensors" ADD COLUMN "enrolment_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "sensors" ADD COLUMN "enrolled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "asset_services" ADD CONSTRAINT "asset_services_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "asset_services_identity_idx" ON "asset_services" USING btree ("asset_id","proto","port","address","source");--> statement-breakpoint
CREATE INDEX "asset_services_asset_idx" ON "asset_services" USING btree ("asset_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "asset_services_port_idx" ON "asset_services" USING btree ("proto","port");