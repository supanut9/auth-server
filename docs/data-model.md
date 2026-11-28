# Data Model

Phase-1 tables:

- `accounts`
- `account_providers`
- `oauth_clients`
- `oauth_client_redirect_uris`
- `authorization_codes`
- `sso_sessions`
- `refresh_token_chains`
- `refresh_tokens`
- `consent_grants`
- `otp_challenges`
- `signed_state_jtis`
- `access_tokens`

Rules:

- generated entity IDs use `UUID v7`
- `accounts.id` maps to token `sub`
- `access_tokens` is audit-oriented and not the normal validation source
- canonical state remains in PostgreSQL
- `schema.sql` is the Atlas desired state, and `migrations/` contains the versioned SQL that repositories run against
- signed flow state carries pending authorization, and `signed_state_jtis` records consumed state identifiers to prevent replay
- tables that reference OAuth clients use the public `oauth_clients.client_id` value for relational consistency with protocol inputs
- redirect URIs are normalized into `oauth_client_redirect_uris` as a one-to-many relation from `oauth_clients`
- `refresh_token_chains` stores the granted scope set so refresh can reissue equivalent access
- `consent_grants` has one row per account and client. Accepting consent updates scopes and last use, clears revocation, and preserves the original grant timestamp.
- `otp_challenges` tracks verification attempts and resend timing so OTP abuse controls can be enforced without relying on the UI

Refer to `../../docs/auth/phase-1-storage-model.md` for the cross-service storage contract.
