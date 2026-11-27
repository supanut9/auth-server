# Config

The Rust server uses environment variables. The local server and dev seeder also load dotenv values when available, giving the process environment precedence. Use `.env.example` for local setup and `.env.vercel.example` for Vercel configuration.

## Server and signing

| Variables | Settings |
| --- | --- |
| `APP_NAME`, `APP_ENV`, `HTTP_ADDR` | Default to `auth-server`, `development`, and `:8050`. `HTTP_ADDR` is the local server's listen address. |
| `PUBLIC_BASE_URL`, `AUTH_UI_BASE_URL`, `JWT_ISSUER` | Required absolute URLs. Local service and UI URLs default in the workspace setup to `http://localhost:8050` and `http://localhost:3005`. |
| `DATABASE_URL` | Required PostgreSQL connection URL. The local Compose service is published on port `55432`. |
| `JWT_SIGNING_ALG`, `PLATFORM_AUDIENCE` | Default to `RS256` and `platform-api`. |
| `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` | Local RSA key files. Use `make dev-keys` to generate a local pair. |
| `JWT_PRIVATE_KEY_PEM`, `JWT_PUBLIC_KEY_PEM` | Inline RSA keys, recommended on Vercel. Inline values take precedence over file paths. |
| `SSO_COOKIE_SECURE`, `SSO_COOKIE_SAME_SITE`, `SSO_COOKIE_DOMAIN` | `SameSite` defaults to `lax`. Use `none` only with `SSO_COOKIE_SECURE=true`. Secure cookies are the default for HTTPS outside development. |
| `POST_LOGOUT_REDIRECT_ALLOWLIST` | Additional origins permitted for post-logout redirects. The auth UI origin is already permitted. |
| `SUPPORT_API_TOKEN` | Bearer token for the support endpoints. Development defaults to `dev-support-token`. Set it in other environments. |
| `FLOW_ENVELOPE_SECRET` | Set a random value of at least 32 bytes after trimming whitespace in production. Other environments use a deterministic fallback derived from `PUBLIC_BASE_URL` when unset. |

`REDIS_URL` and `AUTHORIZATION_REQUEST_TTL` are accepted for compatibility and unused by the runtime. Pending authorization uses signed state with `FLOW_ENVELOPE_TTL`. If supplied, `AUTHORIZATION_REQUEST_TTL` is still parsed as a duration.

## Lifetimes

Duration values retain the pre-cutover syntax. Use forms such as `300ms`, `10m`, `2h45m`, or `720h`. Supported units are `ns`, `us` (also `µs` or `μs`), `ms`, `s`, `m`, and `h`. Express days in hours.

| Variable | Default |
| --- | --- |
| `ACCESS_TOKEN_TTL`, `ID_TOKEN_TTL`, `FLOW_ENVELOPE_TTL`, `OTP_CHALLENGE_TTL` | `10m` |
| `AUTHORIZATION_CODE_TTL` | `5m` |
| `REFRESH_TOKEN_ABSOLUTE_TTL`, `SSO_SESSION_TTL` | `720h` |
| `REFRESH_TOKEN_INACTIVE_TTL` | `168h` |
| `REFRESH_TOKEN_REUSE_GRACE`, `OTP_RESEND_COOLDOWN` | `1m` |

## Providers and email OTP

- Configure all three variables for each enabled provider: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URL`, or `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `GITHUB_REDIRECT_URL`.
- Configure `SMTP_HOST` and `SMTP_FROM` for OTP email delivery. `SMTP_PORT` defaults to `587`. Set `SMTP_USERNAME` and `SMTP_PASSWORD` as required by the relay.
- `OTP_MAX_ATTEMPTS` defaults to `6` and must be positive. `OTP_MAX_RESENDS` defaults to `3` and can be zero. `OTP_RESEND_COOLDOWN` must be positive.
- `FIXED_OTP_CODE` and `OTP_TEST_HINT_ALLOWLIST` are for non-production verification. Production startup rejects both when set.

## Dev seeding

Run `make seed-dev` or `cargo run --bin devseed` against a local database. Example clients include `dev-browser`, `community-web`, `knowledge-web`, `language-web`, `dev-worker`, and `realtime-service`. `DEVSEED_CLIENTS` selects client IDs separated by commas, spaces, or newlines. Supply the intended redirect URIs and secrets when seeding selected clients in a shared database.

| Client | Default redirect URI |
| --- | --- |
| `dev-browser`, `dev-worker` | `http://localhost:8050/dev/callback` |
| `community-web` | `http://localhost:3006/api/auth/oauth2/callback/auth-server` |
| `knowledge-web` | `http://localhost:3007/api/auth/oauth2/callback/auth-server` |
| `language-web` | `http://localhost:3008/api/auth/oauth2/callback/auth-server` |

The seeder derives overrides from the client ID. For `language-web`, use `LANGUAGE_WEB_CLIENT_SECRET`, `LANGUAGE_WEB_REDIRECT_URI`, or `LANGUAGE_WEB_REDIRECT_URIS`. The plural form accepts comma- or newline-separated lists and takes precedence.
