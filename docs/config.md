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
- logout redirect settings
- dev verification client seeding and local callback support

Current local defaults:

- auth-server: `http://localhost:8050`
- auth-ui: `http://localhost:3005`
- PostgreSQL host port: `55432`
- Redis host port: `56379`

Recommended rule:

- fail fast on missing required config
- keep secrets out of code and docs
- separate provider config from general server config
