-- Modify "oauth_clients" table
ALTER TABLE "oauth_clients" ADD COLUMN "logo_uri" character varying(2048) NOT NULL DEFAULT '';
