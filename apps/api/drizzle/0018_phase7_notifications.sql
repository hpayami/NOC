CREATE TABLE "notification_channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"kind" text DEFAULT 'webhook' NOT NULL,
	"url" text NOT NULL,
	"secret" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"min_severity" text DEFAULT 'warning' NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"last_status" text,
	"last_error" text
);
--> statement-breakpoint
CREATE TABLE "notification_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"channel_id" uuid NOT NULL,
	"condition_id" text NOT NULL,
	"event" text NOT NULL,
	"severity" text NOT NULL,
	"status" text NOT NULL,
	"http_status" integer,
	"error" text,
	"attempted_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "notification_states" (
	"channel_id" uuid NOT NULL,
	"condition_id" text NOT NULL,
	"fingerprint" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"last_sent_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "notification_states_channel_id_condition_id_pk" PRIMARY KEY("channel_id","condition_id")
);
--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_channel_id_notification_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_states" ADD CONSTRAINT "notification_states_channel_id_notification_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "notification_deliveries_channel_time_idx" ON "notification_deliveries" USING btree ("channel_id","attempted_at");