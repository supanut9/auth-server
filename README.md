# auth-server

Phase-1 authorization server for the platform.

## Stack

- Go
- Gin
- GORM
- PostgreSQL
- Redis

## Local Defaults

- auth-server: `http://localhost:8050`
- auth-ui: `http://localhost:3005`
- PostgreSQL host port: `55432`
- Redis host port: `56379`

## Responsibilities

- OIDC discovery and JWKS
- OAuth/OIDC protocol endpoints
- auth flow state and action endpoints
- Google and GitHub provider login
- Email OTP flow
- central SSO session management
- token issuance, refresh, revoke, and introspection

## Read First

- `AGENTS.md`
- `docs/overview.md`
- `docs/project-structure.md`
- `docs/config.md`
- `docs/data-model.md`
- `docs/endpoints.md`

## Cross-Service Source Of Truth

Root planning docs remain authoritative for phase 1:

- `../docs/architecture-overview.md`
- `../docs/auth-flow.md`
- `../docs/phase-1-identity.md`
- `../docs/phase-1-token-model.md`
- `../docs/phase-1-storage-model.md`
- `../docs/phase-1-endpoints.md`

## Migrations

- use Atlas to generate migration files from the GORM models
- do not handwrite migration SQL by default
- current workflow:
  - `atlas schema inspect --env gorm --url env://src`
  - `atlas migrate diff <name> --env gorm`

## Dev Signing Keys

The service expects RSA PEM files at the configured JWT key paths.

Example local generation:

```bash
mkdir -p secrets
openssl genrsa -out secrets/jwt-private.pem 2048
openssl rsa -in secrets/jwt-private.pem -pubout -out secrets/jwt-public.pem
```
