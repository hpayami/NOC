CREATE TABLE "sites" (
	"key" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_site_grants" (
	"user_id" uuid NOT NULL,
	"site_key" text NOT NULL,
	"granted_by" uuid,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_site_grants_user_id_site_key_pk" PRIMARY KEY("user_id","site_key")
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "all_sites" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "sites" ADD CONSTRAINT "sites_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_site_grants" ADD CONSTRAINT "user_site_grants_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_site_grants" ADD CONSTRAINT "user_site_grants_site_key_sites_key_fk" FOREIGN KEY ("site_key") REFERENCES "public"."sites"("key") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_site_grants" ADD CONSTRAINT "user_site_grants_granted_by_users_id_fk" FOREIGN KEY ("granted_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;