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
-- Create "oauth_clients" table
CREATE TABLE "oauth_clients" (
  "id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "client_type" character varying(32) NOT NULL,
  "client_secret_hash" character varying(255) NOT NULL DEFAULT '',
  "display_name" character varying(255) NOT NULL,
  "redirect_uris" text NOT NULL,
  "allowed_scopes" text NOT NULL,
  "status" character varying(32) NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
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
-- Create "authorization_requests" table
CREATE TABLE "authorization_requests" (
  "id" uuid NOT NULL,
  "client_id" character varying(128) NOT NULL,
  "account_id" uuid NULL,
  "sso_session_id" uuid NULL,
  "redirect_uri" character varying(2048) NOT NULL,
  "requested_scopes" text NOT NULL,
  "state" character varying(512) NOT NULL,
  "nonce" character varying(512) NULL,
  "pkce_code_challenge" character varying(255) NOT NULL DEFAULT '',
  "pkce_code_challenge_method" character varying(32) NOT NULL DEFAULT '',
  "stage" character varying(64) NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_authorization_requests_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE SET NULL,
  CONSTRAINT "fk_authorization_requests_client" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_authorization_requests_sso_session" FOREIGN KEY ("sso_session_id") REFERENCES "sso_sessions" ("id") ON UPDATE CASCADE ON DELETE SET NULL
);
-- Create index "idx_authorization_requests_account_id" to table: "authorization_requests"
CREATE INDEX "idx_authorization_requests_account_id" ON "authorization_requests" ("account_id");
-- Create index "idx_authorization_requests_client_id" to table: "authorization_requests"
CREATE INDEX "idx_authorization_requests_client_id" ON "authorization_requests" ("client_id");
-- Create index "idx_authorization_requests_expires_at" to table: "authorization_requests"
CREATE INDEX "idx_authorization_requests_expires_at" ON "authorization_requests" ("expires_at");
-- Create index "idx_authorization_requests_sso_session_id" to table: "authorization_requests"
CREATE INDEX "idx_authorization_requests_sso_session_id" ON "authorization_requests" ("sso_session_id");
-- Create index "idx_authorization_requests_stage" to table: "authorization_requests"
CREATE INDEX "idx_authorization_requests_stage" ON "authorization_requests" ("stage");
-- Create "authorization_codes" table
CREATE TABLE "authorization_codes" (
  "id" uuid NOT NULL,
  "code_hash" character varying(255) NOT NULL,
  "authorization_request_id" uuid NOT NULL,
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
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_authorization_codes_account" FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT "fk_authorization_codes_authorization_request" FOREIGN KEY ("authorization_request_id") REFERENCES "authorization_requests" ("id") ON UPDATE CASCADE ON DELETE RESTRICT,
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
-- Create index "idx_consent_grants_client_id" to table: "consent_grants"
CREATE INDEX "idx_consent_grants_client_id" ON "consent_grants" ("client_id");
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
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_otp_challenges_authorization_request" FOREIGN KEY ("authorization_request_id") REFERENCES "authorization_requests" ("id") ON UPDATE CASCADE ON DELETE SET NULL
);
-- Create index "idx_otp_challenges_authorization_request_id" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_authorization_request_id" ON "otp_challenges" ("authorization_request_id");
-- Create index "idx_otp_challenges_email" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_email" ON "otp_challenges" ("email");
-- Create index "idx_otp_challenges_expires_at" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_expires_at" ON "otp_challenges" ("expires_at");
-- Create index "idx_otp_challenges_purpose" to table: "otp_challenges"
CREATE INDEX "idx_otp_challenges_purpose" ON "otp_challenges" ("purpose");
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
