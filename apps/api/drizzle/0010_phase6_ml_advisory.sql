CREATE TYPE "public"."ml_subject_type" AS ENUM('asset', 'flow', 'alert', 'dns_query');--> statement-breakpoint
CREATE TABLE "ml_inference_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"model_name" text NOT NULL,
	"model_version" text NOT NULL,
	"feature_set_version" text NOT NULL,
	"subject_type" "ml_subject_type" NOT NULL,
	"subject_id" text NOT NULL,
	"score" real NOT NULL,
	"explanation" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"features" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"requested_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "ml_results_subject_created_idx" ON "ml_inference_results" USING btree ("subject_type","subject_id","created_at");--> statement-breakpoint
CREATE INDEX "ml_results_created_idx" ON "ml_inference_results" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "ml_results_score_idx" ON "ml_inference_results" USING btree ("score");