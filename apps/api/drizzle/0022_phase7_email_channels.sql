ALTER TABLE "notification_channels" ALTER COLUMN "url" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "notification_channels" ALTER COLUMN "secret" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD COLUMN "config" jsonb;