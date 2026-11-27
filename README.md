# auth-server

Phase-1 authorization server for the platform, built with Rust, Axum, SQLx, and PostgreSQL. It serves OAuth/OIDC, Google and GitHub login, email OTP, central SSO, and support sign-out tooling. The browser pages live in `auth-ui`.

- [Project structure](docs/project-structure.md) and [contributor guidance](AGENTS.md)
- [Configuration](docs/config.md), [data model](docs/data-model.md), and [HTTP endpoints](docs/endpoints.md)
- [HTTP contract tests](contract-tests/README.md) and [cutover deviations](docs/rust-port-deviations.md)

## Local development

The workspace Compose file publishes PostgreSQL on port `55432`. The local server listens on `:8050` by default, and `auth-ui` runs on `http://localhost:3005`.

1. From the parent workspace, start PostgreSQL with `docker compose up -d postgres`.
2. From `auth-server`, copy `.env.example` to `.env`, set the local database URL and base URLs, and run `make dev-keys`. The local binaries load dotenv values without overriding the process environment.
3. Export the local `DATABASE_URL` in your shell for Atlas, then run `make migrate` and `make seed-dev`.
4. Run `make run` to start `cargo run --bin server`. From another terminal, run `make readyz` and `make smoke`.

`make seed-clients` and `make seed-dev` both run `cargo run --bin devseed`. The seeder upserts registered clients and replaces their redirect URIs and secrets from the current configuration. Use `DEVSEED_CLIENTS` to select specific clients. When targeting a shared database, select the client explicitly and supply its intended settings.

```sh
DEVSEED_CLIENTS=language-web \
LANGUAGE_WEB_REDIRECT_URIS='http://localhost:3008/api/auth/oauth2/callback/auth-server,https://example.com/api/auth/oauth2/callback/auth-server' \
cargo run --bin devseed
```

The plural `*_REDIRECT_URIS` takes precedence over `*_REDIRECT_URI` and accepts comma- or newline-separated lists. Confidential clients can use `*_CLIENT_SECRET` overrides. See [configuration](docs/config.md) for seed defaults and additional settings.

## Migrations and SQLx

`schema.sql` is the desired PostgreSQL schema. Atlas uses the `schema` environment in `atlas.hcl` and applies the versioned SQL in `migrations/`.

1. Edit `schema.sql`.
2. Generate the migration with `atlas migrate diff <name> --env schema`.
3. Review the generated migration and `atlas.sum`, then run `make schema-check`.
4. Apply with `make migrate` and an exported `DATABASE_URL`, or pass `--url` explicitly to `atlas migrate apply --env schema`.

The Atlas dev database uses the workspace's `postgres:17-alpine` image. Without Docker, pass `--dev-url` pointing to an empty disposable PostgreSQL database with `search_path=public`.

Builds use the committed `.sqlx/` query metadata. After changing a checked SQL query or its schema, export a local `DATABASE_URL` for a migrated database and regenerate the metadata from the repository root:

```sh
SQLX_OFFLINE=false SQLX_OFFLINE_DIR="$PWD/.sqlx" cargo check --workspace --all-targets
```

## Checks

| Target | What it runs |
| --- | --- |
| `make test` | `cargo test --workspace`. Supply a local `DATABASE_URL` with database creation privileges for `#[sqlx::test]`. |
| `make build` | `cargo build --workspace`. |
| `make check` or `make rs-check` | Formatting, Clippy, workspace tests, `cargo deny check`, and the core dependency check. Install `cargo-deny` 0.22.1. |
| `make readyz` / `make smoke` | Local database readiness / health, readiness, discovery, and JWKS. |
| `make contract-rust` | The standalone HTTP contract suite against an isolated local server and database. |
| `make semgrep` / `make trivy` | Static analysis / filesystem dependency scanning. |
| `make install-hooks` | Install `.githooks/`. Pre-commit runs Semgrep, and pre-push runs Semgrep and Trivy. |

## Vercel

`vercel.json` rewrites requests to `/api/auth`, served by `api/auth.rs` through `VercelLayer`. The function initializes the same Axum router as the local server once per instance. Set `DATABASE_URL` for PostgreSQL and supply the RSA key pair in `JWT_PRIVATE_KEY_PEM` and `JWT_PUBLIC_KEY_PEM`. Use `/readyz` to check database reachability. Both health routes return `request_id` in JSON as well as the `X-Request-Id` response header.

The parent workspace's `docs/auth/` holds the cross-service phase-1 architecture and contracts.
