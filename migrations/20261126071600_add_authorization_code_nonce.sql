-- Modify "authorization_codes" table
ALTER TABLE "authorization_codes" ADD COLUMN "nonce" text NOT NULL DEFAULT '';
