# Auth server HTTP contract tests

The Rust tests exercise the HTTP API at `AUTH_BASE_URL`. They verify response
status, headers, bodies, and redirects without importing server code. Redirects
are disabled and the tests send cookies explicitly.

## Run locally

Install Rust and Cargo, Docker with Compose, Atlas, curl, and OpenSSL. From
`auth-server`, run:

```sh
make contract-rust
```

The target calls `./contract-tests/run-local.sh`. The runner uses the workspace
Compose Postgres on port 55432, creates an `auth_contract_*` database, applies
the checked-in Atlas migrations, and seeds five test clients. It starts the
Rust server on port 8060 with ephemeral RSA keys, fixed OTP, and throwaway
secrets. It supplies isolated configuration to the server and seeder. It runs
the rate-limit test last. It clears the test database's hit log, spends one
request before restarting the server, then verifies the budget persists across
the restart. It stops the server and removes the database and temporary keys. The Compose Postgres service
remains available.

Set `CONTRACT_COMPOSE_FILE` to use a Compose file other than
`../docker-compose.yml`.

## Cutover verification (AUTH-037)

The Go-vs-Rust differential run passed all 200 normalized steps with only
allowlisted differences. The shared-database continuity run passed 67/67
checks for artifacts issued and accepted across both implementations.
`go-final` tags the last Go runtime. The dual-run scripts and recorded results
are in commit `2411406`, which adds the harness after that tag. Commit
`de94811` contains the last pre-cleanup tree with both implementations and
both runners.

## Run against an existing test server

Use a disposable development instance. The tests create accounts, accept
consent, and revoke sessions and refresh chains. There is no need to run the
auth UI or client callback servers.

```sh
cd contract-tests
export AUTH_BASE_URL=http://localhost:8060
export AUTH_UI_BASE_URL=http://localhost:3005
export CONTRACT_OTP_CODE=423817
export CONTRACT_SUPPORT_TOKEN=replace-with-your-test-support-token
cargo test --locked --lib --test contract
# Let the target's OTP resend window expire before this run.
cargo test --locked --test otp_rate_limit -- --ignored
```

The target must use matching OTP and support tokens, RS256, a single published
key, the default token and SSO lifetimes, six OTP attempts, and a positive OTP
resend cooldown. The checked-in runner sets `REFRESH_TOKEN_REUSE_GRACE=0s`. Set
`CONTRACT_REFRESH_REUSE_GRACE_SECS` when targeting a server with a longer grace
window. Use `cargo test --locked --test contract -- --skip sprint0_` to run only
the existing-behavior checks, or `cargo test --locked --test contract sprint0_`
to run the fixed-behavior checks.

| Environment variable | Default or value to match |
| --- | --- |
| `AUTH_BASE_URL` | `http://localhost:8060` |
| `AUTH_UI_BASE_URL` | `http://localhost:3005`. Must match the server's auth UI URL. |
| `CONTRACT_OTP_CODE` | Required. Match the server's `FIXED_OTP_CODE`. |
| `CONTRACT_CRON_SECRET` | Match the server's `CRON_SECRET`. Leave it unset to check the disabled response. |
| `CONTRACT_SUPPORT_TOKEN` | Required. Match the server's `SUPPORT_API_TOKEN`. |
| `CONTRACT_BROWSER_CLIENT_ID`, `CONTRACT_BROWSER_REDIRECT_URI` | `dev-browser`, `http://localhost:8050/dev/callback` |
| `CONTRACT_WEB_CLIENT_ID`, `CONTRACT_WEB_CLIENT_SECRET`, `CONTRACT_WEB_REDIRECT_URI` | `community-web`, `community-web-secret`, `http://localhost:3006/api/auth/oauth2/callback/auth-server` |
| `CONTRACT_WORKER_CLIENT_ID`, `CONTRACT_WORKER_CLIENT_SECRET` | `dev-worker`, `dev-worker-secret` |
| `CONTRACT_INACTIVE_CLIENT_ID`, `CONTRACT_INACTIVE_CLIENT_SECRET` | `knowledge-web`, `knowledge-web-secret`. Seed the confidential client with inactive status and the matching secret. |
| `CONTRACT_MALFORMED_CLIENT_ID`, `CONTRACT_MALFORMED_REDIRECT_URI` | `language-web`, `/contract-callback`. Register the relative URI on this active client. |
| `CONTRACT_BROWSER_DISPLAY_NAME` | `Development Browser Client`. Match the public client's seeded display name. |
| `CONTRACT_APP_NAME`, `CONTRACT_AUDIENCE`, `CONTRACT_ISSUER` | `auth-server`, `platform-api`, and the base URL. Set `CONTRACT_ISSUER` to the exact `JWT_ISSUER` value, including any trailing slashes. |
| `CONTRACT_COOKIE_SECURE`, `CONTRACT_COOKIE_SAME_SITE`, `CONTRACT_COOKIE_DOMAIN` | `false`, `Lax`, and an empty domain. Match the server's cookie configuration. |
| `CONTRACT_LOGOUT_REDIRECT_URI` | An auth UI URL by default. Set this to a registered logout origin to exercise the explicit allowlist. |
| `CONTRACT_REFRESH_REUSE_GRACE_SECS` | `0`. Match the server's reuse grace in seconds. |

## Coverage

- Health and readiness, request ID echo and replacement, OIDC discovery, JWKS,
  and SPKI-derived key IDs.
- Fatal OAuth authorization errors, recoverable redirects, prompt behavior,
  sorted and allowlisted query forwarding, and callback query and fragment
  preservation.
- Public and confidential PKCE S256 login with OTP, SSO cookies, consent,
  authorization code consumption, JWT signature and claim validation, refresh
  rotation and reuse detection, introspection, revocation, and userinfo scope
  gating. Remembered consent permits a direct authorization-code redirect.
- Client credentials with HTTP Basic and form authentication, machine scope
  rules, and userinfo rejection.
- CSRF cookie and token mismatch checks, consent rejection, OTP attempt limits
  and resend cooldown, support summary and sign-out, global logout cookie
  expiry, and logout redirect allowlisting.
- Plain-text 404s, OPTIONS, and trailing-slash redirects.
- OTP rate limiting on the 21st request to one route from one IP.
- Cron cleanup bearer authentication and deleted row counts.
- Sprint 0 checks for switching accounts through OTP, local logout chain
  isolation, and global logout refresh revocation. The account-switch case
  exercises the OTP equivalent because real provider callbacks require a
  configured upstream provider.

OTP and consent actions carry the redirect target in a JSON `redirect_to` field.
An absent CSRF body field produces a 400 binding error. The 403 cases have a
supplied token and a missing or mismatched cookie. See the [cutover deviations](../docs/rust-port-deviations.md) for binding error
wording. The `normalize` module masks volatile values in assertion diagnostics.
The HTTP assertions validate raw responses.
