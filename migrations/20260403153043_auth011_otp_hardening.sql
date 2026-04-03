-- Modify "otp_challenges" table
ALTER TABLE "otp_challenges" ADD COLUMN "last_sent_at" timestamptz;
UPDATE "otp_challenges" SET "last_sent_at" = "created_at" WHERE "last_sent_at" IS NULL;
ALTER TABLE "otp_challenges" ALTER COLUMN "last_sent_at" SET NOT NULL;
-- Create index "idx_otp_challenges_last_sent_at" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_last_sent_at" ON "otp_challenges" ("last_sent_at");
