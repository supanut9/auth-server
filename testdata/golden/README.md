# Golden vectors (AUTH-027)

These **frozen fixtures** capture byte-exact crypto- and format-sensitive
outputs from the Go implementation tagged `go-final`. The Rust tests consume
them **read-only**. Accepted differences are documented in
[`docs/rust-port-deviations.md`](../../docs/rust-port-deviations.md).

## Files

| File | Contents | Historical Go packages |
|---|---|---|
| `jwks.json` | kid derivation, JWKS document bytes, exponent encoding, accepted PEM variants | `internal/adapter/out/jwks` |
| `jwt.json` | access (user, client_credentials, refresh) and ID tokens: header JSON, claims JSON, compact JWS | `internal/application/token` |
| `envelope.json` | provider-state envelope sign output and verify cases with exact error strings | `internal/application/oauth` |
| `hashes.json` | code / refresh / OTP hashes, client-secret storage and matching, PKCE, random token encodings | `token`, `flow`, `identity`, `oauth`, `http`, `cmd/devseed` |
| `scopes.json` | every Go scope splitter/normalizer, side by side on shared inputs, plus client_credentials rules | `oauth`, `token`, `flow`, `http` |
| `masking.json` | email masking (byte-based) | `internal/adapter/in/http` |
| `otp_email.json` | OTP email subject, text, HTML, full MIME message | `internal/adapter/out/mail` |
| `cookies.json` | `Set-Cookie` strings for the SSO and CSRF cookies | `internal/adapter/in/http` |
| `redirects.json` | authorize success/error redirects, auth-ui URLs, provider URLs, post-logout, OTP start | `internal/adapter/in/http` |
| `discovery.json` | `/.well-known/openid-configuration` response | `internal/adapter/in/http` |
| `keys/` | the TEST-ONLY RSA key every signature uses | see `keys/README.md` |

Each file is a JSON object of named **sections**; every section has a
`description` (source function and the rule it encodes) and usually `cases`
(inputs + expected outputs). Strings are stored without HTML escaping, so a
value reads exactly as Go produced it. Raw bytes that are not valid UTF-8 are
given as hex (`*_hex`).

## Reproduce the fixtures

Check out `go-final` in a disposable checkout to inspect the reference
implementation. The tag predates the generator. To regenerate the vectors,
switch that checkout to `696a363` (AUTH-027), which adds the generator tests
and fixture inputs to the same Go implementation. Use the Go version in that
checkout's `go.mod`.

```sh
git switch --detach 696a363
GOLDEN_UPDATE=1 go test ./... -run Golden -count=1
```

Review the diff in the historical checkout after regenerating. Generation is
deterministic. Keep the checked-in Rust fixtures frozen.

The generator tests are named `*_golden_test.go` next to the historical code
they exercise. Writers serialize on `<area>.json.lock` in the disposable
checkout. If generation is killed mid-write, remove the stale lock there.

## Determinism notes

- **Random bytes** (refresh tokens, codes, OTP codes, envelope `jti`, CSRF
  tokens) come from `crypto/rand`, seeded per test with
  `testing/cryptotest.SetGlobalRandom`. Vectors record the raw bytes
  (`raw_hex`) next to the encoding, so the encoding rule is checkable without
  reproducing Go's random stream.
- **Clocks**: services use fixed injected clocks. Two Go paths read the wall
  clock directly, so their vectors are pinned by duration instead of instant:
  `RenderOTPEmail` (`remaining_ms_at_render`, chosen away from minute
  boundaries) and `setSSOCookie` (`Max-Age = int(time.Until(expiresAt).Seconds())`,
  driven with `expiresAt = now + max_age + 0.5s`).
- **RS256** signatures are deterministic (RSASSA-PKCS1-v1_5), so JWTs reproduce
  byte for byte.
- Error strings that wrap Go library text (x509 parse errors, base64/JSON
  decode errors in envelope verify) are recorded as Go emits them. Envelope
  verify errors reach clients as `error_description`; x509 errors are boot-time
  only (marked informational).
