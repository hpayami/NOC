CREATE TABLE "vulnerability_catalog" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"cvss_base_score" real,
	"cvss_vector" text,
	"cvss_version" text,
	"cwe" text[] DEFAULT '{}' NOT NULL,
	"published_at" timestamp with time zone,
	"last_modified_at" timestamp with time zone,
	"known_exploited" boolean DEFAULT false NOT NULL,
	"kev_added_at" timestamp with time zone,
	"kev_due_at" timestamp with time zone,
	"sources" text[] DEFAULT '{}' NOT NULL,
	"imported_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "vuln_catalog_kev_idx" ON "vulnerability_catalog" USING btree ("known_exploited");--> statement-breakpoint
CREATE INDEX "vuln_catalog_imported_idx" ON "vulnerability_catalog" USING btree ("imported_at");