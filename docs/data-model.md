# Data Model

Phase-1 tables:

- `accounts`
- `account_providers`
- `oauth_clients`
- `authorization_requests`
- `authorization_codes`
- `sso_sessions`
- `refresh_token_chains`
- `refresh_tokens`
- `consent_grants`
- `otp_challenges`
- `access_tokens`

Rules:

- all primary keys use `UUID v7`
- `accounts.id` maps to token `sub`
- `access_tokens` is audit-oriented and not the normal validation source
- canonical state remains in PostgreSQL
- Redis is support infrastructure, not the only source of truth
- Atlas-generated SQL migrations define the durable schema source
- GORM models are the schema input for migration generation
- repositories follow the generated migration contract rather than inventing schema independently
- tables that reference OAuth clients use the public `oauth_clients.client_id` value for relational consistency with protocol inputs
- `refresh_token_chains` stores the granted scope set so refresh can reissue equivalent access

Refer to `../../docs/phase-1-storage-model.md` for the cross-service storage contract.
