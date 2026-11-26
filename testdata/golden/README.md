# Golden vectors (AUTH-027)

Byte-exact outputs of the Go auth-server for crypto- and format-sensitive
behavior. The Rust port (AUTH-029 onward) consumes these files **read-only** and
must reproduce them, except where `docs/rust-port-deviations.md` accepts a
difference (e.g. `encoding/json` HTML escaping in JSON response bodies).

## Files

| File | Contents | Owning Go packages |
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

## Workflow

```sh
go test ./...                                          # verify: fails if Go behavior drifts
GOLDEN_UPDATE=1 go test ./... -run Golden -count=1     # rewrite sections after an intended change
```

Review the diff after regenerating. Generation is deterministic: two runs, or a
run from an empty directory, produce identical files.

The tests live in `*_golden_test.go` next to the code they exercise (they call
unexported functions). Every such package carries an identical copy of
`goldenio_golden_test.go` (only the package clause differs); keep the copies in
sync. In update mode, writers serialize on `<area>.json.lock`; if a run is
killed mid-write, delete the stale lock file.

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
