# Rust port

- `crates/auth-core` holds domain and application code and defines ports.
- `crates/auth-adapters` holds outbound adapters and configuration.
- `crates/auth-http` builds the Axum router shared by `src/bin/server.rs` and `api/auth.rs`.
- `contract-tests` is a separate black-box crate with its own lockfile.

## Run locally

```sh
cargo run --bin server
# From another terminal
curl -i http://127.0.0.1:8051/healthz
```

`HTTP_ADDR` overrides the default `127.0.0.1:8051`. The health stub returns a UUID v4 in both `X-Request-Id` and the JSON `request_id` field. Run `make rs-check` for workspace checks with `cargo-deny` 0.22.1 installed.

## Planned Vercel rewrite

After preview verification, replace the Go `routes` rule with the rewrite below. Remove the example comment when applying it to `vercel.json`.

```jsonc
{
  // Switch to the Rust function after the preview is verified.
  "rewrites": [{ "source": "/(.*)", "destination": "/api/auth" }]
}
```
