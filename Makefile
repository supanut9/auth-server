SHELL := /bin/bash

.PHONY: dev-keys migrate schema-check seed-dev seed-clients run test build check readyz smoke semgrep trivy install-hooks hook-pre-commit hook-pre-push

dev-keys:
	mkdir -p secrets
	openssl genrsa -out secrets/jwt-private.pem 2048
	openssl rsa -in secrets/jwt-private.pem -pubout -out secrets/jwt-public.pem

# DATABASE_URL selects the migration target in atlas.hcl.
migrate:
	atlas migrate apply --env schema

# Fails unless schema.sql and migrations/ describe the same schema.
schema-check:
	atlas migrate validate --env schema
	@out="$$(atlas schema diff --env schema --from file://migrations --to env://src 2>&1)" || { echo "$$out"; exit 1; }; \
		echo "$$out"; \
		grep -q "Schemas are synced" <<<"$$out"

seed-dev seed-clients:
	cargo run --bin devseed

run:
	cargo run --bin server

test:
	cargo test --workspace

build:
	cargo build --workspace

check: rs-check

readyz:
	curl -fsS http://localhost:8050/readyz

smoke:
	python3 scripts/smoke.py

semgrep:
	semgrep scan --config auto --error .

trivy:
	trivy filesystem --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .

install-hooks:
	git config core.hooksPath .githooks

hook-pre-commit:
	$(MAKE) semgrep

hook-pre-push:
	$(MAKE) semgrep
	$(MAKE) trivy

.PHONY: rs-fmt rs-lint rs-test rs-deny rs-core-deps rs-check

rs-fmt:
	cargo fmt --all --check

rs-lint:
	cargo clippy --workspace --all-targets -- -D warnings

rs-test: test

rs-deny:
	cargo deny check

rs-core-deps:
	./scripts/check-core-deps.sh

rs-check: rs-fmt rs-lint rs-test rs-deny rs-core-deps

.PHONY: contract-rust

contract-rust:
	./contract-tests/run-local.sh
