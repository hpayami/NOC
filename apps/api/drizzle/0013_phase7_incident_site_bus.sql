ALTER TABLE "incidents" ADD COLUMN "site" text;--> statement-breakpoint
CREATE INDEX "incidents_site_idx" ON "incidents" USING btree ("site");