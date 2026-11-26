# shellcheck shell=bash
# Shared setup for run-differential.sh and run-continuity.sh. Source it; do
# not execute it. It boots the Go and Rust servers side by side with the same
# throwaway RSA key, envelope secret, support token, fixed OTP code and
# clock-insensitive configuration. The caller decides whether each server gets
# its own database (differential) or both share one (continuity).
#
# Ports: Go listens on GO_PORT (8060) and Rust on RUST_PORT (8061). Both
# advertise the same issuer, as they will on Vercel after the cutover.

set -euo pipefail
umask 077

contract_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd -- "$contract_dir/.." && pwd)"
cd -- "$repo_dir"

for tool in atlas cargo curl docker go openssl; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

GO_PORT=8060
RUST_PORT=8061
export CONTRACT_GO_URL="http://localhost:$GO_PORT"
export CONTRACT_RUST_URL="http://localhost:$RUST_PORT"
# One issuer for both implementations. Nothing dereferences it; it only has to
# be identical so tokens, discovery and cookies match across servers.
export CONTRACT_ISSUER=http://auth.contract.test
export AUTH_UI_BASE_URL=http://localhost:3005
export CONTRACT_OTP_CODE=423817
export CONTRACT_BROWSER_CLIENT_ID=dev-browser
export CONTRACT_BROWSER_REDIRECT_URI="$CONTRACT_ISSUER/dev/callback?keep=a+b&state=stale&state=duplicate#keep"
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
export CONTRACT_HINT_EMAIL=contract-hint@example.test
export CONTRACT_AUDIENCE=platform-api
export CONTRACT_APP_NAME=auth-server
export CONTRACT_REFRESH_REUSE_GRACE_SECS=0
flow_secret="$(openssl rand -hex 32)"

curl_local() {
    curl --noproxy '*' --silent --show-error --max-time 2 "$@"
}

for url in "$CONTRACT_GO_URL" "$CONTRACT_RUST_URL"; do
    if curl_local --output /dev/null "$url/healthz" 2>/dev/null; then
        echo "$url already serves HTTP. Stop that service first." >&2
        exit 1
    fi
done

compose() {
    docker compose --env-file /dev/null -f "${CONTRACT_COMPOSE_FILE:-../docker-compose.yml}" "$@"
}

mkdir -p -- "$contract_dir/.keys"
scratch="$(mktemp -d "$contract_dir/.keys/run.XXXXXXXX")"
server_pids=()
created_dbs=()

stop_servers() {
    local pid
    for pid in "${server_pids[@]+"${server_pids[@]}"}"; do
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    server_pids=()
}

cleanup() {
    local result=$?
    trap - EXIT
    stop_servers
    local db
    for db in "${created_dbs[@]+"${created_dbs[@]}"}"; do
        if ! compose exec -T postgres dropdb --username postgres --if-exists --force "$db"; then
            echo "Could not drop test database $db" >&2
            result=1
        fi
    done
    rm -rf -- "$scratch"
    exit "$result"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

compose up -d --no-recreate --wait postgres >/dev/null

db_url() {
    printf 'postgres://postgres:postgres@localhost:55432/%s?sslmode=disable' "$1"
}

# create_db <name>: fresh database at the latest checked-in Atlas migration.
create_db() {
    compose exec -T postgres createdb --username postgres "$1"
    created_dbs+=("$1")
    if ! atlas migrate apply --dir file://migrations --url "$(db_url "$1")" >"$scratch/atlas-$1.log" 2>&1; then
        cat "$scratch/atlas-$1.log" >&2
        exit 1
    fi
}

new_db_name() {
    printf 'auth_%s_%s_%s_%s' "$1" "$(date +%s)" "$$" "$RANDOM"
}

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$scratch/private.pem" 2>"$scratch/openssl.log"
openssl pkey -in "$scratch/private.pem" -pubout -out "$scratch/public.pem"

# Build both implementations once. Binaries run from the empty scratch
# directory so neither autoloads the repository .env.
mkdir -p -- "$scratch/go"
go build -o "$scratch/go/server" ./cmd/server
go build -o "$scratch/go/devseed" ./cmd/devseed
cargo build --quiet --locked --bin server --bin devseed
rust_bin_dir="$(cargo metadata --format-version 1 --no-deps | sed -E 's/.*"target_directory":"([^"]+)".*/\1/')/debug"

impl_bin() {
    case "$1" in
        go) printf '%s/go/%s' "$scratch" "$2" ;;
        rust) printf '%s/%s' "$rust_bin_dir" "$2" ;;
        *) echo "unknown implementation $1" >&2; exit 1 ;;
    esac
}

impl_port() {
    case "$1" in
        go) printf '%s' "$GO_PORT" ;;
        rust) printf '%s' "$RUST_PORT" ;;
    esac
}

# impl_env <impl> <db-name> <command...>: identical configuration for both
# implementations apart from the listen port. GOOGLE_* are dummies so the
# provider start/callback routes are live; HTTPS_PROXY points at the closed
# discard port so a provider code exchange fails locally (provider_error)
# instead of reaching Google. TZ=UTC pins Go's local-time rendering of DB
# timestamps (an accepted deviation) so the comparison is about shape only.
impl_env() {
    local impl=$1 db=$2
    shift 2
    (
        cd -- "$scratch"
        exec env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" TZ=UTC \
            HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=localhost,127.0.0.1 \
            APP_NAME="$CONTRACT_APP_NAME" APP_ENV=development HTTP_ADDR=":$(impl_port "$impl")" GIN_MODE=release \
            DATABASE_URL="$(db_url "$db")" PUBLIC_BASE_URL="$CONTRACT_ISSUER" JWT_ISSUER="$CONTRACT_ISSUER" \
            AUTH_UI_BASE_URL="$AUTH_UI_BASE_URL" POST_LOGOUT_REDIRECT_ALLOWLIST=http://localhost:3406 \
            JWT_PRIVATE_KEY_PATH="$scratch/private.pem" JWT_PUBLIC_KEY_PATH="$scratch/public.pem" \
            FIXED_OTP_CODE="$CONTRACT_OTP_CODE" OTP_TEST_HINT_ALLOWLIST="$CONTRACT_HINT_EMAIL" \
            FLOW_ENVELOPE_SECRET="$flow_secret" SUPPORT_API_TOKEN="$CONTRACT_SUPPORT_TOKEN" \
            REFRESH_TOKEN_REUSE_GRACE="${CONTRACT_REFRESH_REUSE_GRACE_SECS}s" \
            SSO_COOKIE_SECURE=false SSO_COOKIE_SAME_SITE=Lax \
            GOOGLE_CLIENT_ID=contract-google-client GOOGLE_CLIENT_SECRET=contract-google-secret \
            GOOGLE_REDIRECT_URL="$CONTRACT_ISSUER/v1/auth/login/callback/google" \
            DEV_BROWSER_REDIRECT_URI="$CONTRACT_BROWSER_REDIRECT_URI" \
            COMMUNITY_WEB_REDIRECT_URI="$CONTRACT_WEB_REDIRECT_URI" \
            COMMUNITY_WEB_CLIENT_SECRET="$CONTRACT_WEB_CLIENT_SECRET" \
            DEV_WORKER_CLIENT_SECRET="$CONTRACT_WORKER_CLIENT_SECRET" \
            LANGUAGE_WEB_REDIRECT_URI="$CONTRACT_MALFORMED_REDIRECT_URI" \
            DEVSEED_CLIENTS="$CONTRACT_BROWSER_CLIENT_ID,$CONTRACT_WEB_CLIENT_ID,$CONTRACT_WORKER_CLIENT_ID,$CONTRACT_INACTIVE_CLIENT_ID,$CONTRACT_MALFORMED_CLIENT_ID" \
            "$@"
    )
}

# seed <impl> <db-name>: run that implementation's devseed, then deactivate
# the inactive-client fixture exactly like run-local.sh.
seed() {
    if ! impl_env "$1" "$2" "$(impl_bin "$1" devseed)" >"$scratch/devseed-$1-$2.log" 2>&1; then
        cat "$scratch/devseed-$1-$2.log" >&2
        exit 1
    fi
    compose exec -T postgres psql -X -q --username postgres --dbname "$2" --set ON_ERROR_STOP=1 \
        --command "UPDATE oauth_clients SET status = 'inactive' WHERE client_id = '$CONTRACT_INACTIVE_CLIENT_ID'"
    echo "Seeded $2 with the $1 devseed."
}

# start_server <impl> <db-name>: start in its own process group, wait for /readyz.
start_server() {
    local impl=$1 db=$2 url pid attempt
    url="http://localhost:$(impl_port "$impl")"
    set -m
    impl_env "$impl" "$db" "$(impl_bin "$impl" server)" >"$scratch/server-$impl.log" 2>&1 &
    pid=$!
    set +m
    server_pids+=("$pid")
    for ((attempt = 0; attempt < 120; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        if curl_local --fail --output /dev/null "$url/readyz" 2>/dev/null; then
            echo "Started the $impl server on $url against $db."
            return
        fi
        sleep 0.5
    done
    echo "The $impl server did not become ready." >&2
    cat "$scratch/server-$impl.log" >&2
    return 1
}

cargo_tests() {
    cargo test --locked --manifest-path "$contract_dir/Cargo.toml" "$@"
}
