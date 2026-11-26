#!/usr/bin/env bash
# Cutover continuity (AUTH-037): Go on :8060 and Rust on :8061 run at the same
# time against ONE shared database with the same RSA key, envelope secret and
# support token. tests/continuity.rs proves that sessions, codes, refresh
# tokens, JWTs and provider-state envelopes minted by either implementation
# are accepted by the other.
#
# The database is seeded by the Go devseed (as production was), then the Rust
# devseed re-runs over it to prove the seeders agree on an existing DB.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/scripts/dual-harness.sh"

shared_db="$(new_db_name continuity)"
create_db "$shared_db"
echo "Applied Atlas migrations to $shared_db."
seed go "$shared_db"
seed rust "$shared_db"
start_server go "$shared_db"
start_server rust "$shared_db"

CONTRACT_CONTINUITY=1 cargo_tests --test continuity -- --nocapture
