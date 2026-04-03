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
- SMTP-backed OTP delivery when SMTP env vars are configured
- explicit SSO cookie policy and OTP abuse controls for production readiness
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

- `../docs/auth/architecture-overview.md`
- `../docs/auth/auth-flow.md`
- `../docs/auth/phase-1-identity.md`
- `../docs/auth/phase-1-token-model.md`
- `../docs/auth/phase-1-storage-model.md`
- `../docs/auth/phase-1-endpoints.md`

## Migrations

- use Atlas to generate migration files from the GORM models
- do not handwrite migration SQL by default
- current workflow:
  - `atlas schema inspect --env gorm --url env://src`
  - `atlas migrate diff <name> --env gorm`
  - `atlas migrate apply --env gorm`

## Dev Signing Keys

The service expects RSA PEM files at the configured JWT key paths.

Example local generation:

```bash
mkdir -p secrets
openssl genrsa -out secrets/jwt-private.pem 2048
openssl rsa -in secrets/jwt-private.pem -pubout -out secrets/jwt-public.pem
```

## Local Boot

1. start infrastructure from the root workspace:

```bash
docker compose up -d
```

2. copy env and generate keys:

```bash
cp .env.example .env
make dev-keys
```

3. apply migrations and seed demo clients:

```bash
make migrate
make seed-dev
```

4. run the server:

```bash
make run
```

## Production Baseline

- `make check` runs the full test suite and a repo-wide build
- `make readyz` probes the database-backed readiness endpoint
- `make smoke` runs a small local smoke test across health, readiness, discovery, and JWKS
- `GET /healthz` is the liveness endpoint
- `GET /readyz` requires a reachable database and returns `503` if the DB is down
- both health endpoints include a `request_id` field and every response carries `X-Request-Id`

Use `readyz` for deployment probes so the service only receives traffic after the database is reachable.

## Demo Clients

The dev seed command creates:

- public client: `dev-browser`
- confidential client: `community-web`
- confidential secret: `community-web-secret`
- confidential client: `dev-worker`
- confidential secret: `dev-worker-secret`
- confidential client: `realtime-service`
- confidential secret: `dev-realtime-secret`
- demo redirect URI: `http://localhost:8050/dev/callback`
- community web redirect URI: `http://localhost:3006/api/auth/oauth2/callback/auth-server`

Redirect URIs are stored in `oauth_client_redirect_uris` as a one-to-many relation from `oauth_clients`.

Example authorization URL:

```text
http://localhost:8050/v1/oauth2/authorize?response_type=code&client_id=dev-browser&redirect_uri=http%3A%2F%2Flocalhost%3A8050%2Fdev%2Fcallback&scope=openid%20email%20profile%20trading.read&state=demo-state&nonce=demo-nonce&code_challenge=demo-challenge&code_challenge_method=plain
```

The `realtime-service` client is seeded for service-to-service authentication patterns such as token introspection.
