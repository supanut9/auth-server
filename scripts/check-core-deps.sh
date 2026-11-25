#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
deps=$(cargo tree -p auth-core --all-features --target all --prefix none --color never)

if printf '%s\n' "$deps" | grep -E '^(axum|sqlx|reqwest|lettre|tower|vercel_runtime)([[:space:]_-]|$)'; then
    printf '%s\n' 'auth-core has forbidden dependencies.' >&2
    exit 1
fi
