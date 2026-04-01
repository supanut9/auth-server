# Project Structure

Recommended phase-1 package layout should follow hexagonal architecture.

- `cmd/server`
  server bootstrap and wiring
- `internal/config`
  environment-driven configuration
- `internal/domain`
  core entities and domain rules
- `internal/application`
  use cases and orchestration logic
- `internal/port`
  interfaces used by the application layer
- `internal/adapter/in/http`
  Gin handlers, request mapping, response mapping, middleware
- `internal/adapter/out/persistence`
  GORM repositories and PostgreSQL access
- `internal/adapter/out/cache`
  Redis-backed support adapters
- `internal/adapter/out/provider`
  Google and GitHub provider adapters
- `internal/adapter/out/mail`
  email delivery adapter for OTP
- `internal/adapter/out/jwks`
  signing keys and JWKS support
- `migrations`
  schema migrations

Guidelines:

- keep handlers thin
- keep business rules in domain/application layers
- keep framework code in adapters only
- avoid putting business logic in GORM hooks
- use explicit migrations as the long-term schema source
