# Config

Phase-1 config should be environment-driven.

Expected config areas:

- server port and base URLs
- PostgreSQL connection
- Redis connection
- issuer URL
- auth-ui base URL
- JWT signing and JWKS settings
- platform audience and token lifetimes
- authorization request, authorization code, and SSO session lifetimes
- SSO cookie policy
  - configure `SSO_COOKIE_SECURE`, `SSO_COOKIE_SAME_SITE`, and `SSO_COOKIE_DOMAIN`
  - default `SameSite` is `lax`
  - use `SameSite=None` only with `SSO_COOKIE_SECURE=true`
- Google OAuth settings
- GitHub OAuth settings
- Email OTP and mail settings
  - configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM`
  - when `SMTP_HOST` and `SMTP_FROM` are set, `auth-server` sends OTP emails through SMTP
  - OTP request throttling can be tuned with `OTP_MAX_ATTEMPTS`, `OTP_MAX_RESENDS`, and `OTP_RESEND_COOLDOWN`
- logout redirect settings
  - post-logout redirects are restricted to the auth-ui origin
- support API settings
  - configure `SUPPORT_API_TOKEN` for `/v1/support` account summary and sign-out tooling
- dev verification client seeding and local callback support
  - seeds `dev-browser`, `community-web`, `dev-worker`, and `realtime-service`
  - `community-web` callback: `http://localhost:3006/api/auth/oauth2/callback/auth-server`
  - `community-web` secret: `community-web-secret`
  - `realtime-service` secret: `dev-realtime-secret`

Current local defaults:

- auth-server: `http://localhost:8050`
- auth-ui: `http://localhost:3005`
- PostgreSQL host port: `55432`
- Redis host port: `56379`

Recommended rule:

- fail fast on missing required config
- validate required production URLs at startup
- keep secrets out of code and docs
- separate provider config from general server config

Deployment baseline:

- `PUBLIC_BASE_URL`, `AUTH_UI_BASE_URL`, and `JWT_ISSUER` must be absolute URLs
- if a Google or GitHub provider is partially configured, the full client id / secret / redirect URL set must be present
- if SMTP is enabled, `SMTP_FROM` must be set and `SMTP_PORT` must be a valid port number
- if `SSO_COOKIE_SAME_SITE=none`, `SSO_COOKIE_SECURE` must be `true`
- `SUPPORT_API_TOKEN` must be configured; development falls back to `dev-support-token`
- OTP settings must remain positive and finite
- run `make smoke` after local or deploy startup to confirm request IDs, health, discovery, and JWKS responses
- `X-Request-Id` is emitted on every response and surfaced in `/healthz` and `/readyz`
