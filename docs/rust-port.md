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

## Schema

`schema.sql` is the schema source of truth (plan decision D5, AUTH-026). The Rust port has no GORM, so Atlas now diffs `migrations/` against this desired-state SQL file instead of the GORM loader. `migrations/` and `atlas.sum` did not change, and neither did the database schema.

- New migration: edit `schema.sql`, run `atlas migrate diff <name> --env schema`, review the file, then apply it with `atlas migrate apply --env schema`.
- Drift check: `make schema-check` runs `atlas migrate validate` and fails unless `schema.sql` and `migrations/` describe the same schema.
- `schema.sql` was generated with `atlas schema inspect --format '{{ sql . "  " }}'` from a scratch database migrated to `20260522162000`. At generation time it was also verified to have no diff from the GORM loader output (`atlas schema diff --env gorm`).
- The `gorm` env in `atlas.hcl` stays until cutover so the Go service keeps working. Until AUTH-039 the schema is frozen: any schema change goes through Atlas on the Go side first, and `schema.sql` must be updated in the same change.
