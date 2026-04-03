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
-- Modify "oauth_clients" table
ALTER TABLE "oauth_clients" DROP COLUMN "redirect_uris";
