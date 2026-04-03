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
- Google OAuth settings
- GitHub OAuth settings
- Email OTP and mail settings
  - configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM`
  - when `SMTP_HOST` and `SMTP_FROM` are set, `auth-server` sends OTP emails through SMTP
- logout redirect settings
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
- run `make smoke` after local or deploy startup to confirm request IDs, health, discovery, and JWKS responses
- `X-Request-Id` is emitted on every response and surfaced in `/healthz` and `/readyz`
