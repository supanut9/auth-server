# AGENTS.md

This service is the phase-1 authorization server.

## Stack

- Go
- Gin
- GORM
- PostgreSQL
- Redis

## Architecture

Use hexagonal architecture.

Rules:

- domain and application logic stay independent of Gin, GORM, PostgreSQL, Redis, and provider SDK details
- Gin belongs to inbound adapters
- GORM/PostgreSQL/Redis/provider integrations belong to outbound adapters
- business rules must not depend directly on framework or infrastructure packages

## Service Responsibilities

- OIDC discovery and JWKS
- OAuth/OIDC protocol endpoints
- auth flow state/action endpoints
- provider integration for Google and GitHub
- Email OTP flow
- central SSO session management
- token issuance, refresh, revoke, and introspection

## Do Not Own

- rendered login pages
- rendered consent pages
- rendered OTP pages

Those belong to `auth-ui`.

## Read Before Coding

- `../docs/auth/phase-1-endpoints.md`
- `../docs/auth/phase-1-storage-model.md`
- `../docs/auth/phase-1-token-model.md`
- `../docs/auth/phase-1-identity.md`

## Data Model Rules

- all primary keys use `UUID v7`
- `accounts.id` maps to token `sub`
- `access_tokens` is audit-oriented, not the normal validation source
- `authorization_requests` and `authorization_codes` stay separate
- `refresh_token_chains` and `refresh_tokens` stay separate

## Endpoint Split

- `/v1/oauth2/*` and `/v1/oidc/*` are protocol endpoints
- `/v1/auth/*` are auth flow action/state endpoints
- `/.well-known/*` are discovery endpoints

## Implementation Advice

- keep handlers thin
- put flow rules in application/domain services, not Gin handlers
- avoid putting business logic in GORM hooks
- generate migration files from the GORM data model with Atlas
- do not handwrite migration SQL by default
- do not rely on GORM `AutoMigrate` as the durable schema workflow
