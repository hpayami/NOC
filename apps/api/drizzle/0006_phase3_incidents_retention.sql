ALTER TYPE "public"."retention_data_class" ADD VALUE 'observations' BEFORE 'pcap';--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "opened_by" uuid;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_opened_by_users_id_fk" FOREIGN KEY ("opened_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;