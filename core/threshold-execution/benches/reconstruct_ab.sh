#!/usr/bin/env bash
# Before/after benchmark of the optimistic reconstruction of openings (`open_reconstruct`), on one binary: once
# with the defaults (optimistic path in front of the decoder) and once with `MPC_RECONSTRUCT=decoder` (the
# decoder alone, as before). Criterion group names carry the series, so both runs keep their results under
# target/criterion and `ab_table.py` prints the before/after table from them.
#
#   core/threshold-execution/benches/reconstruct_ab.sh
#   core/threshold-execution/benches/reconstruct_ab.sh 'n13_t4'      # extra arguments are criterion filters
set -euo pipefail
cd "$(dirname "$0")/../../.."
CRITERION_DIR=${CARGO_TARGET_DIR:-target}/criterion
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), $(nproc) logical CPUs"
echo "== open_reconstruct, after (defaults)"
cargo bench -p threshold-execution -F testing --bench open_reconstruct -- --noplot "$@"
echo "== open_reconstruct, before (MPC_RECONSTRUCT=decoder)"
MPC_RECONSTRUCT=decoder cargo bench -p threshold-execution -F testing --bench open_reconstruct -- --noplot "$@"
python3 core/threshold-execution/benches/ab_table.py "$CRITERION_DIR"
