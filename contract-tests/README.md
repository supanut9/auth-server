# Auth server HTTP contract tests

The Rust tests exercise the HTTP API at `AUTH_BASE_URL`. They verify response
status, headers, bodies, and redirects without importing server code. Redirects
are disabled and the tests send cookies explicitly. The same tests can target a
Go or Rust server with matching fixtures.

## Run locally against Go

Install Rust and Cargo, Go, Docker with Compose, Atlas, curl, and OpenSSL. From
the auth-server repository, run:

```sh
./contract-tests/run-local.sh
```

The runner uses the workspace Compose Postgres on port 55432, creates an
`auth_contract_*` database, applies the checked-in Atlas migrations, and seeds
five test clients. It starts the server on port 8060 with ephemeral RSA keys,
fixed OTP, and throwaway secrets. It runs the server and seeder from a scratch
directory to isolate their dotenv autoloading. It runs the rate-limit test last
after restarting the server, then stops the server and removes the database and
temporary keys. The Compose Postgres service remains available.

Set `AUTH_IMPL=rust` to run the same suite against the Rust binaries
(`make contract-rust`). `CONTRACT_COMPOSE_FILE` points the runners at a Compose
file other than `../docker-compose.yml`.

## Go and Rust side by side

Two more runners boot Go on port 8060 and Rust on port 8061 at the same time.
They share `scripts/dual-harness.sh`, which builds both implementations,
generates one throwaway RSA key, and gives both servers the same envelope
secret, support token, fixed OTP code, issuer (`http://auth.contract.test`), and
configuration. It also sets dummy `GOOGLE_*` values so the provider routes are
live, and points `HTTPS_PROXY` at the closed local port 9 so a provider code
exchange fails locally with `provider_error` instead of reaching Google. Both
runners drop their databases, keys, and processes on exit.

### Differential run

```sh
./contract-tests/run-differential.sh   # or: make contract-diff
```

Each server gets its own fresh migrated database, seeded by its own devseed.
`tests/differential.rs` runs one deterministic script of about 200 requests
against each server. The script covers health, discovery, JWKS, authorize
errors and redirects, OTP and consent, the token grants, refresh rotation and
reuse, introspection, revocation, userinfo, CSRF failures, support, logout,
provider start and callback, and router quirks. It records the status, every
response header except transport headers, and the body. `normalize::Normalizer`
replaces volatile values with stable aliases such as `<uuid-v7#3>` and
`<opaque#2>`. The aliases are numbered by first use, so relationships between
values must also match. JWTs and flow envelopes are expanded so their claims
and payload bytes are compared. Redirect query strings keep their order and
encoding.

The run fails unless every difference matches an entry in the commented
`ALLOWLIST` in `tests/differential.rs`. Each entry names the port plan's
accepted deviation. The report lists every difference and the allowlist hit
counts. Set `CONTRACT_DIFF_DUMP=<dir>` to also write the normalized observations
of both runs as JSON. The test is skipped unless `CONTRACT_DIFFERENTIAL=1`.

### Cutover continuity run

```sh
./contract-tests/run-continuity.sh     # or: make contract-continuity
```

Both servers share one database, seeded by the Go devseed and then by the Rust
devseed. `tests/continuity.rs` checks in both directions that artifacts minted by
one implementation work on the other:

- (a) SSO cookies work for `/v1/auth/me`, consent accept, and `prompt=none`
  authorize.
- (b) Authorization codes redeem with PKCE, and a code consumed on one server
  is consumed on the other.
- (c) Refresh tokens rotate across implementations.
- (d) Reuse of a token rotated by one server is detected by the other, and the
  whole chain is revoked on both.
- (e) Access and ID tokens give identical userinfo and introspection answers,
  and the JWKS documents are byte-identical.
- (f) A provider-state envelope signed by one server passes verification on the
  other. The callback then fails at the provider exchange with 502. A replay at
  the signer fails with `oauth: jti replay` because the JTI was burned in the
  shared table.
- (g) Support sign-out and global logout on one server revoke the session and
  refresh chain on the other.

The test is skipped unless `CONTRACT_CONTINUITY=1`.

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
# Restart the target or let its OTP resend window expire before this run.
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
| `CONTRACT_SUPPORT_TOKEN` | Required. Match the server's `SUPPORT_API_TOKEN`. |
| `CONTRACT_BROWSER_CLIENT_ID`, `CONTRACT_BROWSER_REDIRECT_URI` | `dev-browser`, `http://localhost:8050/dev/callback` |
| `CONTRACT_WEB_CLIENT_ID`, `CONTRACT_WEB_CLIENT_SECRET`, `CONTRACT_WEB_REDIRECT_URI` | `community-web`, `community-web-secret`, `http://localhost:3006/api/auth/oauth2/callback/auth-server` |
| `CONTRACT_WORKER_CLIENT_ID`, `CONTRACT_WORKER_CLIENT_SECRET` | `dev-worker`, `dev-worker-secret` |
| `CONTRACT_INACTIVE_CLIENT_ID` | `knowledge-web`. Seed it with inactive status. |
| `CONTRACT_MALFORMED_CLIENT_ID`, `CONTRACT_MALFORMED_REDIRECT_URI` | `language-web`, `/contract-callback`. Register the relative URI on this active client. |
| `CONTRACT_BROWSER_DISPLAY_NAME` | `Development Browser Client`. Match the public client's seeded display name. |
| `CONTRACT_APP_NAME`, `CONTRACT_AUDIENCE`, `CONTRACT_ISSUER` | `auth-server`, `platform-api`, and the base URL without a trailing slash. |
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
- Sprint 0 checks for switching accounts through OTP, local logout chain
  isolation, and global logout refresh revocation. The account-switch case
  exercises the OTP equivalent because real provider callbacks require a
  configured upstream provider.

OTP and consent actions carry the redirect target in a JSON `redirect_to` field.
An absent CSRF body field produces a 400 binding error. The 403 cases have a
supplied token and a missing or mismatched cookie. The binding error text may
differ across implementations as described in the port plan.

The `normalize` module supplies JSON, redirect, and request ID helpers for
later differential comparisons. The HTTP assertions validate raw responses
before any normalization.
