# Rust port — known deviations from Go

Production has run the Rust server since 2026-11-27. The `go-final` tag is the Go reference for contract parity (plan §3, decision D3). `make contract-rust` checks the black-box HTTP contract, and the Rust workspace tests consume the frozen golden vectors in `testdata/golden/` for crypto, tokens, cookies, redirects, masking, OTP mail and discovery.

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
| Client IP (AUTH-048) | trusted forwarding headers from all peers | Vercel edge headers in priority order, with the socket peer as fallback. Standalone uses the socket peer | Internal |
| Panic response | 500 from gin.Recovery | same, and CORS headers are still present | Client-visible (only on a crash) |
| Protocol response headers (AUTH-042) | no cache directives or bearer challenge | token and introspection send `Cache-Control: no-store` and `Pragma: no-cache` on success and error. Userinfo 401s send a bearer challenge | Client-visible |
| Authorization-code PKCE (AUTH-043) | consumed the code before checking the verifier | failed PKCE leaves the code usable through its existing expiry | Client-visible |
| Protocol client status (AUTH-044) | authenticated inactive clients at token, revoke, and introspect | rejects inactive clients with `401 invalid_client`. Empty status counts as active | Client-visible |
| ID token claims (AUTH-045) | omitted `azp` and `sid` and used `JWT_ISSUER` verbatim | includes `azp` and the SSO `sid` when present. ID token `iss` matches discovery. Access token `iss` uses the configured issuer verbatim | Client-visible |
| Access token checks (AUTH-046) | JWT introspection and Userinfo accepted ID tokens | verifies the platform audience and presence of `scope` for both endpoints. ID tokens introspect as inactive and get a 401 from Userinfo | Client-visible |
| Consent persistence (AUTH-047) | concurrent inserts could create duplicate grants | one grant per account and client, written with an atomic upsert | Internal |
| OTP correctness (AUTH-049) | kept the casing at OTP start and account lookup, compared hashes directly, allowed expired resend, and truncated email minutes | lowercases OTP start emails, looks up emails case-insensitively, compares OTP hashes in constant time, rejects expired resend, and rounds email minutes up | Client-visible |

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
| OTP rate limiter (AUTH-048) | per-instance route middleware | shared PostgreSQL window checked before the body is read, with the same 20/60 limit and 429 response. Returns 503 if the limiter is unavailable |

## Unchanged on purpose

These behaviors were preserved at cutover. The port plan tracks them individually (§7):
- A missing SSO session on refresh returns the repository error; the HTTP layer maps every refresh error to `invalid_grant`.
