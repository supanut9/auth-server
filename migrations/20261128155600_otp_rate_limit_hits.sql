-- Create "otp_rate_limit_hits" table
CREATE TABLE "otp_rate_limit_hits" (
  "key" text NOT NULL,
  "hit_at" timestamptz NOT NULL
);
-- Create index "idx_otp_rate_limit_hits_key_hit_at" to table: "otp_rate_limit_hits"
CREATE INDEX "idx_otp_rate_limit_hits_key_hit_at" ON "otp_rate_limit_hits" ("key", "hit_at");
