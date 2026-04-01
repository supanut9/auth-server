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

Refer to `../../docs/phase-1-storage-model.md` for the cross-service storage contract.
