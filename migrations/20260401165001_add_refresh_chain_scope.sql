-- Modify "refresh_token_chains" table
ALTER TABLE "refresh_token_chains" ADD COLUMN "scope" text NOT NULL;
