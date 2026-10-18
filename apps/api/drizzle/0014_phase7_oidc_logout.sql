CREATE TABLE "oidc_logout_tokens" (
	"jti" text PRIMARY KEY NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "external_sid" text;--> statement-breakpoint
CREATE INDEX "refresh_tokens_external_sid_idx" ON "refresh_tokens" USING btree ("external_sid");