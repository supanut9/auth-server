-- Modify "authorization_codes" table
ALTER TABLE "authorization_codes" DROP CONSTRAINT "fk_authorization_codes_authorization_request";
-- Modify "otp_challenges" table
ALTER TABLE "otp_challenges" DROP CONSTRAINT "fk_otp_challenges_authorization_request";
-- Drop "authorization_requests" table
DROP TABLE "authorization_requests";
