#!/usr/bin/env bash
set -euo pipefail
umask 077

contract_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$contract_dir/.."

for tool in atlas cargo curl docker go openssl; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

export AUTH_BASE_URL=http://localhost:8060
export AUTH_UI_BASE_URL=http://localhost:3005
export CONTRACT_OTP_CODE=423817
export CONTRACT_BROWSER_CLIENT_ID=dev-browser
export CONTRACT_BROWSER_REDIRECT_URI="$AUTH_BASE_URL/dev/callback?keep=a+b&state=stale&state=duplicate#keep"
export CONTRACT_WEB_CLIENT_ID=community-web
export CONTRACT_WEB_CLIENT_SECRET=contract-only-web-secret
export CONTRACT_WEB_REDIRECT_URI=http://localhost:3006/api/auth/oauth2/callback/auth-server
export CONTRACT_WORKER_CLIENT_ID=dev-worker
export CONTRACT_WORKER_CLIENT_SECRET=contract-only-worker-secret
export CONTRACT_INACTIVE_CLIENT_ID=knowledge-web
export CONTRACT_MALFORMED_CLIENT_ID=language-web
export CONTRACT_MALFORMED_REDIRECT_URI=/contract-callback
export CONTRACT_SUPPORT_TOKEN="$(openssl rand -hex 32)"
export CONTRACT_LOGOUT_REDIRECT_URI='http://localhost:3406/signed-out?from=contract#return'
export CONTRACT_ISSUER="$AUTH_BASE_URL"
export CONTRACT_AUDIENCE=platform-api
export CONTRACT_APP_NAME=auth-server
export CONTRACT_COOKIE_SECURE=false
export CONTRACT_COOKIE_SAME_SITE=Lax
export CONTRACT_COOKIE_DOMAIN=
export CONTRACT_REFRESH_REUSE_GRACE_SECS=0

curl_local() {
    curl --noproxy '*' --silent --show-error --max-time 2 "$@"
}

if curl_local --output /dev/null "$AUTH_BASE_URL/healthz" 2>/dev/null; then
    echo "Port 8060 already serves HTTP. Stop that service before running the contract suite." >&2
    exit 1
fi

compose() {
    docker compose --env-file /dev/null -f "${CONTRACT_COMPOSE_FILE:-../docker-compose.yml}" "$@"
}

mkdir -p -- "$contract_dir/.keys"
scratch="$(mktemp -d "$contract_dir/.keys/run.XXXXXXXX")"
db_name="auth_contract_$(date +%s)_$$_${RANDOM}"
db_url="postgres://postgres:postgres@localhost:55432/$db_name?sslmode=disable"
server_pid=
db_created=

stop_server() {
    if [[ -n "$server_pid" ]]; then
        kill -TERM -- "-$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        server_pid=
    fi
}

cleanup() {
    local result=$?
    trap - EXIT
    stop_server
    if [[ -n "$db_created" ]]; then
        if ! compose exec -T postgres dropdb --username postgres --if-exists --force "$db_name"; then
            echo "Could not drop test database $db_name" >&2
            result=1
        fi
    fi
    rm -rf -- "$scratch"
    exit "$result"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

compose up -d --no-recreate --wait postgres
compose exec -T postgres createdb --username postgres "$db_name"
db_created=1

# atlas.hcl's gorm environment uses the same checked-in migration directory.
if ! atlas migrate apply --dir file://migrations --url "$db_url" >"$scratch/atlas.log" 2>&1; then
    cat "$scratch/atlas.log" >&2
    exit 1
fi
echo "Applied Atlas migrations to the test database."

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$scratch/private.pem" 2>"$scratch/openssl.log"
openssl pkey -in "$scratch/private.pem" -pubout -out "$scratch/public.pem"

# Both commands use godotenv/autoload. Only the compiled program runs in the
# empty scratch directory, while go run resolves the package from the repo.
cat > "$scratch/launch" <<'LAUNCH'
#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
exec "$@"
LAUNCH
chmod +x "$scratch/launch"

test_env() {
    env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
        APP_NAME="$CONTRACT_APP_NAME" APP_ENV=development HTTP_ADDR=:8060 GIN_MODE=release \
        DATABASE_URL="$db_url" PUBLIC_BASE_URL="$AUTH_BASE_URL" JWT_ISSUER="$CONTRACT_ISSUER" \
        AUTH_UI_BASE_URL="$AUTH_UI_BASE_URL" POST_LOGOUT_REDIRECT_ALLOWLIST=http://localhost:3406 \
        JWT_PRIVATE_KEY_PATH="$scratch/private.pem" JWT_PUBLIC_KEY_PATH="$scratch/public.pem" \
        FIXED_OTP_CODE="$CONTRACT_OTP_CODE" OTP_TEST_HINT_ALLOWLIST=contract-hint@example.test \
        FLOW_ENVELOPE_SECRET="$flow_secret" SUPPORT_API_TOKEN="$CONTRACT_SUPPORT_TOKEN" \
        REFRESH_TOKEN_REUSE_GRACE="${CONTRACT_REFRESH_REUSE_GRACE_SECS}s" \
        SSO_COOKIE_SECURE="$CONTRACT_COOKIE_SECURE" SSO_COOKIE_SAME_SITE="$CONTRACT_COOKIE_SAME_SITE" \
        DEV_BROWSER_REDIRECT_URI="$CONTRACT_BROWSER_REDIRECT_URI" \
        COMMUNITY_WEB_REDIRECT_URI="$CONTRACT_WEB_REDIRECT_URI" \
        COMMUNITY_WEB_CLIENT_SECRET="$CONTRACT_WEB_CLIENT_SECRET" \
        DEV_WORKER_CLIENT_SECRET="$CONTRACT_WORKER_CLIENT_SECRET" \
        LANGUAGE_WEB_REDIRECT_URI="$CONTRACT_MALFORMED_REDIRECT_URI" \
        DEVSEED_CLIENTS="$CONTRACT_BROWSER_CLIENT_ID,$CONTRACT_WEB_CLIENT_ID,$CONTRACT_WORKER_CLIENT_ID,$CONTRACT_INACTIVE_CLIENT_ID,$CONTRACT_MALFORMED_CLIENT_ID" \
        "${run_cmd[@]}" "$(impl_target "$1")"
}

# AUTH_IMPL=go (default) runs ./cmd/<name> with go run; AUTH_IMPL=rust runs
# the prebuilt Rust binaries of the same name. Both start in the empty
# scratch directory so neither autoloads the repo .env.
case "${AUTH_IMPL:-go}" in
    go)
        run_cmd=(go run -exec "\"$scratch/launch\"")
        impl_target() { printf '%s' "$1"; }
        ;;
    rust)
        cargo build --quiet --locked --bin server --bin devseed
        rust_bin_dir="$(cargo metadata --format-version 1 --no-deps | sed -E 's/.*"target_directory":"([^"]+)".*/\1/')/debug"
        run_cmd=("$scratch/launch")
        impl_target() { printf '%s' "$rust_bin_dir/$(basename -- "$1")"; }
        ;;
    *) echo "AUTH_IMPL must be go or rust" >&2; exit 1 ;;
esac
echo "Contract target implementation: ${AUTH_IMPL:-go}"

flow_secret="$(openssl rand -hex 32)"
if ! test_env ./cmd/devseed >"$scratch/devseed.log" 2>&1; then
    cat "$scratch/devseed.log" >&2
    exit 1
fi
echo "Seeded the contract clients."
compose exec -T postgres psql -X --username postgres --dbname "$db_name" --set ON_ERROR_STOP=1 \
    --command "UPDATE oauth_clients SET status = 'inactive' WHERE client_id = 'knowledge-web'"

start_server() {
    # Put go run and its child in one process group for reliable cleanup.
    set -m
    test_env ./cmd/server >"$scratch/server.log" 2>&1 &
    server_pid=$!
    set +m

    for ((attempt = 0; attempt < 120; attempt++)); do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            break
        fi
        if curl_local --fail --output /dev/null "$AUTH_BASE_URL/readyz" 2>/dev/null; then
            return
        fi
        sleep 0.5
    done
    echo "Contract server did not become ready." >&2
    cat "$scratch/server.log" >&2
    return 1
}

cargo_tests() {
    cargo test --locked --manifest-path "$contract_dir/Cargo.toml" "$@"
}

start_server
result=0
cargo_tests --lib --test contract || result=$?

# The OTP error test has used the resend route. Reset the in-memory window.
stop_server
start_server
cargo_tests --test otp_rate_limit -- --ignored || result=$?
exit "$result"
