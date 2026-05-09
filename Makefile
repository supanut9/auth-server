SHELL := /bin/bash

.PHONY: dev-keys migrate seed-dev seed-clients run test build check readyz smoke

dev-keys:
	mkdir -p secrets
	openssl genrsa -out secrets/jwt-private.pem 2048
	openssl rsa -in secrets/jwt-private.pem -pubout -out secrets/jwt-public.pem

migrate:
	atlas migrate apply --env gorm

seed-dev:
	go run ./cmd/devseed

seed-clients:
	go run ./cmd/devseed

run:
	go run ./cmd/server

test:
	go test ./internal/... ./cmd/server

build:
	go build ./...

check:
	go test ./... && go build ./...

readyz:
	curl -fsS http://localhost:8050/readyz

smoke:
	python3 scripts/smoke.py
