# AGENTS.md

This service is the phase-1 authorization server. It serves OAuth/OIDC discovery, JWKS, protocol and auth flow endpoints, Google and GitHub login, email OTP, central SSO sessions, and token issuance, refresh, revocation, and introspection. `auth-ui` owns rendered login, consent, and OTP pages.

## Stack and architecture

Use Rust, Axum, SQLx, and PostgreSQL. Keep the four workspace crates organized around hexagonal architecture.

- `auth-core` owns domain types, application services, and port traits. It must stay independent of Axum, SQLx, reqwest, lettre, Tower, PostgreSQL, and provider implementations. `./scripts/check-core-deps.sh` checks its dependency tree.
- `auth-adapters` implements outbound ports for PostgreSQL, providers, mail, JWT signing and JWKS, and system services. It also loads and validates configuration.
- `auth-http` owns the Axum router, middleware, HTTP handlers, and bootstrap wiring. Keep handlers thin and map service errors to HTTP responses here.
- `auth-server` is the root binary crate. `src/bin/server.rs` and the Vercel function `api/auth.rs` serve the shared router. `src/bin/devseed.rs` seeds OAuth clients.

Inject the clock, ID generator, and random source through ports so tests can reproduce deterministic results. Keep flow and token rules in `auth-core`.

## Read before coding

- `docs/overview.md`, `docs/project-structure.md`, `docs/config.md`, `docs/data-model.md`, and `docs/endpoints.md`
- `../docs/auth/phase-1-endpoints.md`, `../docs/auth/phase-1-storage-model.md`, `../docs/auth/phase-1-token-model.md`, and `../docs/auth/phase-1-identity.md` in the parent workspace
- `docs/rust-port-deviations.md` for compatibility decisions and `testdata/golden/README.md` for the frozen fixtures

## Data model rules

- Use UUID v7 for generated entity IDs. `accounts.id` maps to token `sub`.
- Keep the signed authorization flow state separate from durable `authorization_codes`.
- Keep `refresh_token_chains` and `refresh_tokens` separate.
- Use `access_tokens` for audit. Normal access-token validation uses signed JWTs.

## Endpoint split

- `/v1/oauth2/*` and `/v1/oidc/*` are protocol endpoints.
- `/v1/auth/*` are auth flow action and state endpoints.
- `/.well-known/*` are discovery endpoints.

## Schema and local commands

- Edit `schema.sql` as the desired state. Use `atlas migrate diff <name> --env schema`, review the generated migration, run `make schema-check`, and apply with `make migrate` using an exported `DATABASE_URL`.
- Generate new migrations with Atlas by default. Preserve applied migration files and let Atlas update `migrations/atlas.sum`.
- After query or schema changes, export a local migrated `DATABASE_URL` and run `SQLX_OFFLINE=false SQLX_OFFLINE_DIR="$PWD/.sqlx" cargo check --workspace --all-targets` to refresh `.sqlx/`.
- Use `make run` for the local server and `make seed-dev` or `make seed-clients` for `cargo run --bin devseed`. On a shared database, set `DEVSEED_CLIENTS` and supply that client's intended configuration before seeding.
- Use `make build`, `make test`, `make check`, and `make contract-rust` as described in `README.md`. The SQLx runtime tests require a local PostgreSQL connection even when query metadata is loaded offline.
