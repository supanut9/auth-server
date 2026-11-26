# Rust port — known deviations from Go

The Rust server targets **contract parity** with the Go server (plan §3, decision D3). It passes the same black-box contract suite (`contract-tests/`, `AUTH_IMPL=rust`), and byte-level golden vectors from Go (`testdata/golden/`) for crypto, tokens, cookies, redirects, masking, OTP mail and discovery.

This file lists every known difference. Anything not listed here is meant to behave exactly like Go. Report a new difference by adding a row here, and fix it in Rust unless it belongs to one of the categories below.

Legend:
- **Client-visible**: a consumer app or auth-ui could see it in a response.
- **Edge**: only reachable with malformed or unusual input.
- **Internal**: logs, errors at boot, or tests only.

## Intentional improvements

| Area | Go | Rust | Visibility |
|---|---|---|---|
| JWKS key loading | never checked that the public key matches the private key | boot fails with `jwt key pair mismatch` | Internal (boot) |
| devseed upsert | update, delete and insert are 3 separate statements | one transaction per client, so a failure never leaves a prod client without redirect URIs | Internal |
| Client IP when the peer is unknown | gin returns `""` and ignores headers | reads `X-Forwarded-For` / `X-Real-IP`. Required on Vercel, which gives no peer address, so OTP rate-limit keys stay per-client | Internal |
| Panic response | 500 from gin.Recovery | same, and CORS headers are still present | Client-visible (only on a crash) |

## Accepted deviations (plan §3)

| Area | Go | Rust | Visibility |
|---|---|---|---|
| Bind errors on JSON action endpoints | gin validator text, e.g. `Key: '...' Error:Field validation for 'ClientID' failed on the 'required' tag` | `client_id is required` / `invalid JSON body`. Only the first missing field is named | Client-visible (`error_description`, shown by auth-ui) |
| JSON decoding of bodies | invalid UTF-8 / lone surrogate escapes become U+FFFD | 400 `invalid_request` | Edge |
| Timestamps read from the DB | rendered in the process time zone | always UTC (Vercel is UTC anyway) | Client-visible in support API only off-Vercel |
| `multipart/form-data` on token/revoke/introspect | parsed by `PostForm` | treated as an empty form (clients send urlencoded) | Edge |
| Request logs | GORM non-JSON lines, gin debug banner | JSON access log only (query string dropped in both since AUTH-022) | Internal |

## Edge-case parsing differences

| Area | Go | Rust | Visibility |
|---|---|---|---|
| Empty path parameter (`/v1/clients//public-info`) | handler runs with `clientID=""` | 404 | Edge |
| Malformed percent-escape in the path (`/%zz`) | 400 from `net/http` | 404 | Edge |
| Invalid UTF-8 in cookies, paths or query values | raw bytes kept | replaced with U+FFFD | Edge |
| Encoded fixed path segments (`/heal%74hz`) | matched after decoding | matched by re-escaping. Assumes fixed segments use only `A-Za-z0-9-._~`, which holds for every route | Edge |
| IPv6 literal in `redirect_uri` | Go's parser | Rust std parser. 14 cases checked identical; not proven for all inputs | Edge |
| `GODEBUG=urlstrictcolons=0` | would accept `https://a:1:2/` | always strict (Go 1.26 default) | Edge (no such setting in prod) |
| Malformed UUID ids | sent to Postgres, which returns `22P02` | rejected before the query with the same `22P02` text. `urn:uuid:` and Postgres's odd hyphen placements differ | Edge |
| Unique-constraint violations in repositories | raw Postgres error text | `record already exists` (`RepoError::Conflict`) | Internal (no handler shows it) |
| `strings.EqualFold` | full Unicode simple folding | per-character lower/upper folding, dotless ı excluded; covers ASCII, Kelvin sign, ſ, Greek sigma, ß, İ | Edge |
| Config URL validation messages | `url.Parse` wording, e.g. "first path segment in URL cannot contain colon" | same inputs fail; some messages read "must be an absolute URL" | Internal (boot) |
| Non-string JWT claims in introspection | `fmt.Sprint` | close approximation | Edge (only foreign tokens) |

## Error text differences (not client-visible)

| Area | Note |
|---|---|
| X.509 / ASN.1 key parse errors | the prefix (`parse private key:` / `parse public key:`) and the error kind match; the detail differs. Boot only. The certificate reader also validates less than Go |
| JWT verifier errors | golang-jwt wording; JSON details from serde. Handlers discard the text (`invalid_token` / `active:false`) |
| Provider JSON decode errors | serde text, except empty → `EOF` and truncated → `unexpected EOF`, as in Go. Can surface in a 502 `error_description` only when Google or GitHub return malformed JSON |
| Provider transport errors (502 `provider_error`) | `error_description` carries the HTTP client's transport error text (Go `net/http` vs `reqwest`); status and `error` code match. Found by the differential run |
| devseed fatal errors | no `log` timestamp prefix; an unreachable DB gives sqlx's pool-timeout text. A malformed `.env` may apply the lines before the error, where godotenv applies none |

## Runtime differences

| Area | Go | Rust |
|---|---|---|
| Outbound HTTP User-Agent (Google/GitHub) | `Go-http-client/1.1` | `auth-server` |
| SMTP connect timeout | none | 30 s |
| SMTP on error | connection dropped | sends `QUIT`, then closes |
| SMTP AUTH detection | any advertised AUTH | AUTH with a mechanism lettre knows (PLAIN/LOGIN/XOAUTH2) |
| `updated_at` on update | GORM's own wall clock | the injected clock (same in prod; deterministic in tests) |
| Expiry arithmetic | wraps on overflow | saturates |
| OTP rate limiter | route middleware | request extractor running before the body is read; same keys, limits and 429 body |

## Unchanged on purpose

These Go quirks are deliberately kept so the differential tests stay meaningful. They are fixed after cutover, one card each (plan §7):
- PKCE is checked after the code is consumed.
- ID tokens pass introspection and userinfo.
- Inactive clients pass the token, revoke and introspect endpoints.
- There is no `nonce` in the ID token.
- Token `iss` is untrimmed while discovery's `issuer` is trimmed.
- OTP email is case-sensitive, and the code compare is not constant-time.
- Resend can revive an expired OTP challenge.
- A missing SSO session on refresh returns the repository error; the HTTP layer maps every refresh error to `invalid_grant`.
- Consent upsert can race and create duplicate rows, because the table has no unique constraint.
