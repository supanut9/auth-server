-- Create "signed_state_jtis" table
CREATE TABLE "signed_state_jtis" (
  "jti" character varying(64) NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL,
  PRIMARY KEY ("jti")
);
-- Create index "idx_signed_state_jtis_expires_at" to table: "signed_state_jtis"
CREATE INDEX "idx_signed_state_jtis_expires_at" ON "signed_state_jtis" ("expires_at");
