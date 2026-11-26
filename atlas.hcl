# Legacy: desired state loaded from the Go GORM models via cmd/atlasloader.
# Kept only until the Go code is removed at cutover; use env "schema" for new
# migrations (see README "Migrations").
data "external_schema" "gorm" {
  program = [
    "go",
    "run",
    "-mod=mod",
    "./cmd/atlasloader",
  ]
}

env "gorm" {
  src = data.external_schema.gorm.url
  dev = "docker://postgres/17/dev?search_path=public"

  migration {
    dir = "file://migrations"
  }
}

# Desired state = schema.sql (rust-port decision D5, AUTH-026).
# The dev database uses the same postgres:17-alpine image as the workspace
# docker-compose, so it works offline once that image is pulled. Without
# Docker, pass a disposable empty local database instead, e.g.
#   --dev-url "postgres://postgres:postgres@localhost:55432/<scratch_db>?sslmode=disable&search_path=public"
env "schema" {
  src = "file://schema.sql"
  dev = "docker://postgres/17-alpine/dev?search_path=public"

  migration {
    dir = "file://migrations"
  }
}
