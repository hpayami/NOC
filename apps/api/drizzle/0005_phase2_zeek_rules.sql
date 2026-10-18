ALTER TABLE "detection_rules" ADD COLUMN "enabled" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "action" text;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "classtype" text;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "rule_set" text;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "content" text;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD COLUMN "imported_by" uuid;--> statement-breakpoint
CREATE INDEX "security_events_correlation_gin_idx" ON "security_events" USING gin ("correlation_ids");