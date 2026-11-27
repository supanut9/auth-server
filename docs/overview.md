# Overview

`auth-server` is the phase-1 Rust authorization server. It owns OIDC discovery and JWKS, OAuth/OIDC protocol endpoints, auth flow state and actions, Google and GitHub login, email OTP, central SSO sessions, and token issuance, refresh, revocation, and introspection. The `auth-ui` service renders login, consent, and OTP pages.

The local `server` binary and the Vercel function `api/auth.rs` share the Axum router in `auth-http`. Vercel rewrites requests to `/api/auth`. The function builds its router once per instance and serves a plain-text 500 if startup fails. The router uses a lazy SQLx pool with up to two PostgreSQL connections.

PostgreSQL holds account, session, and OAuth state. Pending browser authorization uses signed flow state, and issued authorization codes are stored as separate records. See [project structure](project-structure.md) and [data model](data-model.md) for the implementation, and the parent workspace's `docs/auth/` for cross-service decisions.
