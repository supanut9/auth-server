-- Modify "authorization_codes" table
ALTER TABLE "authorization_codes" ALTER COLUMN "authorization_request_id" DROP NOT NULL;
