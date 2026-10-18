ALTER TABLE "sensors" ADD COLUMN "rules_bundle_sha256" text;--> statement-breakpoint
ALTER TABLE "sensors" ADD COLUMN "rules_bundle_applied_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "sites" text[] DEFAULT '{}' NOT NULL;