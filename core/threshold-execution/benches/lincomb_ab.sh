#!/usr/bin/env bash
# A/B benchmark of the linear-combination backends on one binary: PRSS.Next, PRZS.Next and PRSS-Mask.Next
# (`prss_lincomb`) and the local partial decryption of noise-flooding decryption (`ddec_lincomb`).
#
# Each bench runs twice, with the backend auto-detected (AVX-512 IFMA where available) and with
# `MPC_LINCOMB_BACKEND=scalar`; criterion group names carry the backend, so both runs keep their results under
# target/criterion and `lincomb_table.py` prints the before/after table from them.
#
#   core/threshold-execution/benches/lincomb_ab.sh                    # both benches
#   BENCHES=ddec_lincomb core/threshold-execution/benches/lincomb_ab.sh
#   BENCH_PRIMITIVES=przs,mask BENCHES=prss_lincomb core/threshold-execution/benches/lincomb_ab.sh
#
# Extra arguments go to criterion (e.g. a filter such as 'n13_t4/16384').
set -euo pipefail
cd "$(dirname "$0")/../../.."
BENCHES=${BENCHES:-"prss_lincomb ddec_lincomb"}
CRITERION_DIR=${CARGO_TARGET_DIR:-target}/criterion
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), $(nproc) logical CPUs"
for bench in $BENCHES; do
    if [ ! -f "core/threshold-execution/benches/$bench.rs" ]; then
        echo "== $bench: not in this checkout, skipped"
        continue
    fi
    echo "== $bench, auto-detected backend"
    cargo bench -p threshold-execution -F testing --bench "$bench" -- --noplot "$@"
    echo "== $bench, MPC_LINCOMB_BACKEND=scalar"
    MPC_LINCOMB_BACKEND=scalar cargo bench -p threshold-execution -F testing --bench "$bench" -- --noplot "$@"
done
python3 core/threshold-execution/benches/lincomb_table.py "$CRITERION_DIR"
