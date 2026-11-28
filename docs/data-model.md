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
- `otp_rate_limit_hits`
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
- `otp_challenges` tracks verification attempts and resend timing. New OTP challenges store a trimmed, lowercase email.
- Email lookups for accounts and OTP challenges are case-insensitive. Reads preserve the stored spelling.
- `otp_rate_limit_hits` records admitted OTP requests by route and IP. The composite index supports the sliding window, and a PostgreSQL transaction lock serializes admission per key across instances.

The daily cleanup removes expired `signed_state_jtis`, authorization codes
and OTP challenges that expired more than 24 hours ago, and OTP rate-limit
hits older than one hour. Each run returns deletion counts for all four tables.

Refer to `../../docs/auth/phase-1-storage-model.md` for the cross-service storage contract.
