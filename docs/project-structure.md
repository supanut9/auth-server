# Project Structure

The workspace follows hexagonal architecture.

| Crate | Responsibility |
| --- | --- |
| `crates/auth-core` | Domain types, OAuth validation, PKCE and envelopes, flow, identity, and token services, and port traits for storage, providers, mail, time, IDs, and randomness. |
| `crates/auth-adapters` | SQLx repositories, configuration, JWT signing and JWKS, Google and GitHub clients, SMTP delivery, and system port implementations. |
| `crates/auth-http` | Shared Axum router, middleware, HTTP handlers, protocol response mapping, and composition of services and adapters. |
| `auth-server` (root) | `src/bin/server.rs` for local serving, `src/bin/devseed.rs` for OAuth client seeding, and `api/auth.rs` for Vercel. |

`auth-core` must stay independent of Axum, SQLx, reqwest, lettre, and Tower. `scripts/check-core-deps.sh` enforces the boundary. Keep use cases in the core services, use ports to inject collaborators, and keep framework-specific request parsing and responses in `auth-http`.

- `schema.sql` defines the desired schema and `migrations/` contains the versioned SQL generated with Atlas.
- `.sqlx/` contains the offline query metadata used at compile time.
- `testdata/golden/` contains frozen interoperability fixtures used by workspace tests.
- `contract-tests/` is an independent black-box crate with its own lockfile. It exercises the HTTP API over the network.
