-- Create index "idx_consent_grants_account_id_client_id" to table: "consent_grants"
CREATE UNIQUE INDEX "idx_consent_grants_account_id_client_id" ON "consent_grants" ("account_id", "client_id");
