-- Modify "authorization_requests" table
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_name" character varying(64) NOT NULL DEFAULT '';
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_account_id" character varying(255) NOT NULL DEFAULT '';
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_email" character varying(320) NOT NULL DEFAULT '';
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_email_verified" boolean NOT NULL DEFAULT false;
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_display_name" character varying(255) NOT NULL DEFAULT '';
ALTER TABLE "authorization_requests" ADD COLUMN "pending_provider_avatar_url" character varying(2048) NOT NULL DEFAULT '';
