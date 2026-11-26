#!/usr/bin/env bash
# Differential run (AUTH-037): Go on :8060 and Rust on :8061, each on its own
# fresh migrated database seeded by its own devseed, with the same RSA key,
# envelope secret, support token, fixed OTP code and configuration. One
# scripted request sequence (tests/differential.rs) runs against both and every
# normalized difference must be in the test's allowlist.
#
# Optional: CONTRACT_DIFF_DUMP=<dir> writes the normalized observations of
# both runs as JSON for inspection.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/scripts/dual-harness.sh"

go_db="$(new_db_name diff_go)"
rust_db="$(new_db_name diff_rust)"
create_db "$go_db"
create_db "$rust_db"
echo "Applied Atlas migrations to $go_db and $rust_db."
seed go "$go_db"
seed rust "$rust_db"
start_server go "$go_db"
start_server rust "$rust_db"

CONTRACT_DIFFERENTIAL=1 cargo_tests --test differential -- --nocapture
