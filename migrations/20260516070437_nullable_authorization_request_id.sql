-- Modify "authorization_codes" table
ALTER TABLE "authorization_codes" DROP CONSTRAINT "fk_authorization_codes_authorization_request", ALTER COLUMN "authorization_request_id" DROP NOT NULL, ADD CONSTRAINT "fk_authorization_codes_authorization_request" FOREIGN KEY ("authorization_request_id") REFERENCES "authorization_requests" ("id") ON UPDATE CASCADE ON DELETE SET NULL;
