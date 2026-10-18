ALTER TABLE "response_actions" ADD COLUMN "justification" text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE "response_actions" ADD COLUMN "parameters" jsonb DEFAULT '{}'::jsonb NOT NULL;