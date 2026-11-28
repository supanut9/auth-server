-- schema.sql: Atlas desired-state schema for auth-server (PostgreSQL 17, schema "public").
--
-- This file is the durable schema source of truth (rust-port decision D5,
-- card AUTH-026). It replaces the GORM models + cmd/atlasloader as the input
-- to `atlas migrate diff`. The versioned files in migrations/ (and atlas.sum)
-- remain the only thing applied to databases; this file is never applied
-- directly.
--
-- Change the schema:
--   1. edit this file
--   2. atlas migrate diff <name> --env schema     # writes a new migrations/ file
--   3. review the generated SQL
--   4. atlas migrate apply --env schema --url "$DATABASE_URL"
--
-- Check it matches migrations/ (must print "The migration directory is synced
-- with the desired state, no changes to be made"):
--   atlas migrate diff --env schema
--
-- Regenerate from a database at the latest migration (sanity check only; the
-- body below is verbatim `atlas schema inspect` output):
--   atlas schema inspect --url "postgres://...?sslmode=disable&search_path=public" \
--     --format '{{ sql . "  " }}'

-- Create "accounts" table
CREATE TABLE "accounts" (
  "id" uuid NOT NULL,
  "primary_verified_email" character varying(320) NOT NULL,
  "display_name" character varying(255) NOT NULL,
  "avatar_url" character varying(2048) NOT NULL DEFAULT '',
  "status" character varying(32) NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id")
);
-- Create index "idx_accounts_primary_verified_email" to table: "accounts"
CREATE UNIQUE INDEX "idx_accounts_primary_verified_email" ON "accounts" ("primary_verified_email");
-- Create index "idx_accounts_status" to table: "accounts"
CREATE INDEX "idx_accounts_status" ON "accounts" ("status");
-- Create "otp_challenges" table
CREATE TABLE "otp_challenges" (
  "id" uuid NOT NULL,
  "authorization_request_id" uuid NULL,
  "email" character varying(320) NOT NULL,
  "purpose" character varying(64) NOT NULL,
  "code_hash" character varying(255) NOT NULL,
  "attempt_count" integer NOT NULL DEFAULT 0,
  "resend_count" integer NOT NULL DEFAULT 0,
  "expires_at" timestamptz NOT NULL,
  "verified_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "last_sent_at" timestamptz NOT NULL,
  PRIMARY KEY ("id")
);
-- Create index "idx_otp_challenges_authorization_request_id" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_authorization_request_id" ON "otp_challenges" ("authorization_request_id");
-- Create index "idx_otp_challenges_email" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_email" ON "otp_challenges" ("email");
-- Create index "idx_otp_challenges_expires_at" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_expires_at" ON "otp_challenges" ("expires_at");
-- Create index "idx_otp_challenges_last_sent_at" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_last_sent_at" ON "otp_challenges" ("last_sent_at");
-- Create index "idx_otp_challenges_purpose" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_purpose" ON "otp_challenges" ("purpose");
-- Create "otp_rate_limit_hits" table
CREATE TABLE "otp_rate_limit_hits" (
  "key" text NOT NULL,
  "hit_at" timestamptz NOT NULL
);
-- Create index "idx_otp_rate_limit_hits_key_hit_at" to table: "otp_rate_limit_hits"
CREATE INDEX "idx_otp_rate_limit_hits_key_hit_at" ON "otp_rate_limit_hits" ("key", "hit_at");
-- Create "signed_state_jtis" table
CREATE TABLE "signed_state_jtis" (
  "jti" character varying(64) NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL,
  PRIMARY KEY ("jti")
);
-- Create index "idx_signed_state_jtis_expires_at" to table: "signed_state_jtis"
CREATE INDEX "idx_signed_state_jtis_expires_at" ON "signed_state_jtis" ("expires_at");
-- Create "oauth_clients" table
CREATE TABLE "oauth_clients" (
  "id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "client_type" character varying(32) NOT NULL,
  "client_secret_hash" character varying(255) NOT NULL DEFAULT '',
  "display_name" character varying(255) NOT NULL,
  "allowed_scopes" text NOT NULL,
  "status" character varying(32) NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "logo_uri" character varying(2048) NOT NULL DEFAULT '',
  PRIMARY KEY ("id")
);
-- Create index "idx_oauth_clients_client_id" to table: "oauth_clients"
CREATE UNIQUE INDEX "idx_oauth_clients_client_id" ON "oauth_clients" ("client_id");
-- Create index "idx_oauth_clients_client_type" to table: "oauth_clients"
CREATE INDEX "idx_oauth_clients_client_type" ON "oauth_clients" ("client_type");
-- Create index "idx_oauth_clients_status" to table: "oauth_clients"
CREATE INDEX "idx_oauth_clients_status" ON "oauth_clients" ("status");
-- Create "sso_sessions" table
CREATE TABLE "sso_sessions" (
  "id" uuid NOT NULL,
  "account_id" uuid NOT NULL,
  "status" character varying(32) NOT NULL,
  "login_method" character varying(64) NOT NULL,
  "authenticated_at" timestamptz NOT NULL,
  "last_seen_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "revoked_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_sso_sessions_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT
);
-- Create index "idx_sso_sessions_account_id" to table: "sso_sessions"
CREATE INDEX "idx_sso_sessions_account_id" ON "sso_sessions" ("account_id");
-- Create index "idx_sso_sessions_expires_at" to table: "sso_sessions"
CREATE INDEX "idx_sso_sessions_expires_at" ON "sso_sessions" ("expires_at");
-- Create index "idx_sso_sessions_status" to table: "sso_sessions"
CREATE INDEX "idx_sso_sessions_status" ON "sso_sessions" ("status");
-- Create "access_tokens" table
CREATE TABLE "access_tokens" (
  "id" uuid NOT NULL,
  "jti" character varying(255) NOT NULL,
  "sid" character varying(255) NOT NULL,
  "account_id" uuid NULL,
  "client_id" character varying(128) NOT NULL,
  "sso_session_id" uuid NULL,
  "audience" character varying(255) NOT NULL,
  "scope" text NOT NULL,
  "issued_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "status" character varying(32) NOT NULL,
  "revoked_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_access_tokens_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE SET NULL,
  CONSTRAINT "fk_access_tokens_client" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_access_tokens_sso_session" FOREIGN KEY ("sso_session_id") REFERENCES "sso_sessions" ("id") ON UPDATE CASCADE ON DELETE SET NULL
);
-- Create index "idx_access_tokens_account_id" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_account_id" ON "access_tokens" ("account_id");
-- Create index "idx_access_tokens_client_id" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_client_id" ON "access_tokens" ("client_id");
-- Create index "idx_access_tokens_expires_at" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_expires_at" ON "access_tokens" ("expires_at");
-- Create index "idx_access_tokens_jti" to table: "access_tokens"
CREATE UNIQUE INDEX "idx_access_tokens_jti" ON "access_tokens" ("jti");
-- Create index "idx_access_tokens_sid" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_sid" ON "access_tokens" ("sid");
-- Create index "idx_access_tokens_sso_session_id" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_sso_session_id" ON "access_tokens" ("sso_session_id");
-- Create index "idx_access_tokens_status" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_status" ON "access_tokens" ("status");
-- Create "account_providers" table
CREATE TABLE "account_providers" (
  "id" uuid NOT NULL,
  "account_id" uuid NOT NULL,
  "provider" character varying(64) NOT NULL,
  "provider_account_id" character varying(255) NOT NULL,
  "provider_email" character varying(320) NOT NULL DEFAULT '',
  "provider_email_verified" boolean NOT NULL DEFAULT false,
  "profile_name" character varying(255) NOT NULL DEFAULT '',
  "profile_avatar_url" character varying(2048) NOT NULL DEFAULT '',
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_account_providers_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT
);
-- Create index "idx_account_providers_account_id" to table: "account_providers"
CREATE INDEX "idx_account_providers_account_id" ON "account_providers" ("account_id");
-- Create index "idx_provider_account" to table: "account_providers"
CREATE UNIQUE INDEX "idx_provider_account" ON "account_providers" ("provider", "provider_account_id");
-- Create "authorization_codes" table
CREATE TABLE "authorization_codes" (
  "id" uuid NOT NULL,
  "code_hash" character varying(255) NOT NULL,
  "authorization_request_id" uuid NULL,
  "account_id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "sso_session_id" uuid NULL,
  "redirect_uri" character varying(2048) NOT NULL,
  "granted_scopes" text NOT NULL,
  "pkce_code_challenge" character varying(255) NOT NULL DEFAULT '',
  "pkce_code_challenge_method" character varying(32) NOT NULL DEFAULT '',
  "auth_time" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "consumed_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "nonce" text NOT NULL DEFAULT '',
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_authorization_codes_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_authorization_codes_client" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_authorization_codes_sso_session" FOREIGN KEY ("sso_session_id") REFERENCES "sso_sessions" ("id") ON UPDATE CASCADE ON DELETE SET NULL
);
-- Create index "idx_authorization_codes_account_id" to table: "authorization_codes"
CREATE INDEX "idx_authorization_codes_account_id" ON "authorization_codes" ("account_id");
-- Create index "idx_authorization_codes_authorization_request_id" to table: "authorization_codes"
CREATE INDEX "idx_authorization_codes_authorization_request_id" ON "authorization_codes" ("authorization_request_id");
-- Create index "idx_authorization_codes_client_id" to table: "authorization_codes"
CREATE INDEX "idx_authorization_codes_client_id" ON "authorization_codes" ("client_id");
-- Create index "idx_authorization_codes_code_hash" to table: "authorization_codes"
CREATE UNIQUE INDEX "idx_authorization_codes_code_hash" ON "authorization_codes" ("code_hash");
-- Create index "idx_authorization_codes_expires_at" to table: "authorization_codes"
CREATE INDEX "idx_authorization_codes_expires_at" ON "authorization_codes" ("expires_at");
-- Create index "idx_authorization_codes_sso_session_id" to table: "authorization_codes"
CREATE INDEX "idx_authorization_codes_sso_session_id" ON "authorization_codes" ("sso_session_id");
-- Create "consent_grants" table
CREATE TABLE "consent_grants" (
  "id" uuid NOT NULL,
  "account_id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "granted_scopes" text NOT NULL,
  "granted_at" timestamptz NOT NULL,
  "last_used_at" timestamptz NOT NULL,
  "revoked_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_consent_grants_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_consent_grants_client" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE RESTRICT
);
-- Create index "idx_consent_grants_account_id" to table: "consent_grants"
CREATE INDEX "idx_consent_grants_account_id" ON "consent_grants" ("account_id");
-- Create index "idx_consent_grants_account_id_client_id" to table: "consent_grants"
CREATE UNIQUE INDEX "idx_consent_grants_account_id_client_id" ON "consent_grants" ("account_id", "client_id");
-- Create index "idx_consent_grants_client_id" to table: "consent_grants"
CREATE INDEX "idx_consent_grants_client_id" ON "consent_grants" ("client_id");
-- Create "oauth_client_redirect_uris" table
CREATE TABLE "oauth_client_redirect_uris" (
  "id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "redirect_uri" character varying(2048) NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_oauth_clients_redirect_uris" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE CASCADE
);
-- Create index "idx_oauth_client_redirect_uris_client_id" to table: "oauth_client_redirect_uris"
CREATE INDEX "idx_oauth_client_redirect_uris_client_id" ON "oauth_client_redirect_uris" ("client_id");
-- Create index "idx_oauth_client_redirect_uris_client_redirect" to table: "oauth_client_redirect_uris"
CREATE UNIQUE INDEX "idx_oauth_client_redirect_uris_client_redirect" ON "oauth_client_redirect_uris" ("client_id", "redirect_uri");
-- Create "refresh_token_chains" table
CREATE TABLE "refresh_token_chains" (
  "id" uuid NOT NULL,
  "account_id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "sso_session_id" uuid NOT NULL,
  "device_session_id" character varying(255) NOT NULL,
  "status" character varying(32) NOT NULL,
  "absolute_expires_at" timestamptz NOT NULL,
  "inactive_expires_at" timestamptz NOT NULL,
  "last_used_at" timestamptz NOT NULL,
  "revoked_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "scope" text NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_refresh_token_chains_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_refresh_token_chains_client" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_refresh_token_chains_sso_session" FOREIGN KEY ("sso_session_id") REFERENCES "sso_sessions" ("id") ON UPDATE CASCADE ON DELETE RESTRICT
);
-- Create index "idx_refresh_token_chains_absolute_expires_at" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_absolute_expires_at" ON "refresh_token_chains" ("absolute_expires_at");
-- Create index "idx_refresh_token_chains_account_id" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_account_id" ON "refresh_token_chains" ("account_id");
-- Create index "idx_refresh_token_chains_client_id" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_client_id" ON "refresh_token_chains" ("client_id");
-- Create index "idx_refresh_token_chains_device_session_id" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_device_session_id" ON "refresh_token_chains" ("device_session_id");
-- Create index "idx_refresh_token_chains_inactive_expires_at" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_inactive_expires_at" ON "refresh_token_chains" ("inactive_expires_at");
-- Create index "idx_refresh_token_chains_sso_session_id" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_sso_session_id" ON "refresh_token_chains" ("sso_session_id");
-- Create index "idx_refresh_token_chains_status" to table: "refresh_token_chains"
CREATE INDEX "idx_refresh_token_chains_status" ON "refresh_token_chains" ("status");
-- Create "refresh_tokens" table
CREATE TABLE "refresh_tokens" (
  "id" uuid NOT NULL,
  "refresh_token_chain_id" uuid NOT NULL,
  "token_hash" character varying(255) NOT NULL,
  "issued_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "used_at" timestamptz NULL,
  "replaced_by_token_id" uuid NULL,
  "revoked_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_refresh_tokens_refresh_token_chain" FOREIGN KEY ("refresh_token_chain_id") REFERENCES "refresh_token_chains" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_refresh_tokens_replaced_by_token" FOREIGN KEY ("replaced_by_token_id") REFERENCES "refresh_tokens" ("id") ON UPDATE CASCADE ON DELETE SET NULL
);
-- Create index "idx_refresh_tokens_expires_at" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_expires_at" ON "refresh_tokens" ("expires_at");
-- Create index "idx_refresh_tokens_refresh_token_chain_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_refresh_token_chain_id" ON "refresh_tokens" ("refresh_token_chain_id");
-- Create index "idx_refresh_tokens_replaced_by_token_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_replaced_by_token_id" ON "refresh_tokens" ("replaced_by_token_id");
-- Create index "idx_refresh_tokens_token_hash" to table: "refresh_tokens"
CREATE UNIQUE INDEX "idx_refresh_tokens_token_hash" ON "refresh_tokens" ("token_hash");
