# TEST-ONLY golden key

These files are a **public, throwaway RSA-2048 key used only by the golden
test vectors** (AUTH-027). It is committed on purpose, signs nothing real, and
must never be configured as `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` in any
environment.

| File | Encoding |
|---|---|
| `test-only-rsa-2048-private-pkcs1.pem` | `RSA PRIVATE KEY` (PKCS#1) — the source of truth |
| `test-only-rsa-2048-private-pkcs8.pem` | `PRIVATE KEY` (PKCS#8), derived |
| `test-only-rsa-2048-public-pkix.pem` | `PUBLIC KEY` (PKIX/SPKI), derived |
| `test-only-rsa-2048-cert.pem` | self-signed X.509 certificate for the same key, derived (serial 27, 2026-01-01..2036-01-01) |

The key was generated deterministically from a fixed seed
(`GOLDEN_KEYGEN=1 go test ./internal/adapter/out/jwks -run TestGoldenGenerateTestKey -count=1`,
`testing/cryptotest.SetGlobalRandom(seed 27)`). `TestGoldenKeyFilesConsistent`
checks on every run that the derived files are exactly what Go produces from
the PKCS#1 key. Regenerating is never needed; doing so changes every JWT vector.

`.semgrepignore` excludes this directory (and `jwt.json` / `envelope.json`,
which carry tokens signed with it) from the secret detectors.
