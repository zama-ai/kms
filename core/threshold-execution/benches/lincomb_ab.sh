#!/usr/bin/env bash
# A/B benchmark, on one binary, of the linear-combination backends and of the optimistic reconstruction:
#   prss_lincomb  PRSS.Next, PRZS.Next and PRSS-Mask.Next      (after: AVX-512 IFMA, before: MPC_LINCOMB_BACKEND=scalar)
#   ddec_lincomb  local partial decryption of noise flooding   (after: AVX-512 IFMA, before: MPC_LINCOMB_BACKEND=scalar,
#                                                               plus the previous fold implementation in the same run)
#   open_lincomb  reconstruction step of openings              (after: optimistic + decoder, before: MPC_RECONSTRUCT=decoder)
#
# Each bench runs twice, "after" with the defaults (backend auto-detected) and "before" with the environment
# variable that disables the new path; criterion group names carry the series, so both runs keep their
# results under target/criterion and `lincomb_table.py` prints the before/after tables from them.
#
#   core/threshold-execution/benches/lincomb_ab.sh                    # all benches
#   BENCHES=open_lincomb core/threshold-execution/benches/lincomb_ab.sh
#   BENCH_PRIMITIVES=przs,mask BENCHES=prss_lincomb core/threshold-execution/benches/lincomb_ab.sh
#
# Extra arguments go to criterion (e.g. a filter such as 'n13_t4/16384' or 'robust_open').
set -euo pipefail
cd "$(dirname "$0")/../../.."
BENCHES=${BENCHES:-"prss_lincomb ddec_lincomb open_lincomb"}
CRITERION_DIR=${CARGO_TARGET_DIR:-target}/criterion
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), $(nproc) logical CPUs"
for bench in $BENCHES; do
    if [ ! -f "core/threshold-execution/benches/$bench.rs" ]; then
        echo "== $bench: not in this checkout, skipped"
        continue
    fi
    case "$bench" in
        open_lincomb) before="MPC_RECONSTRUCT=decoder" ;;
        *) before="MPC_LINCOMB_BACKEND=scalar" ;;
    esac
    echo "== $bench, after (defaults)"
    cargo bench -p threshold-execution -F testing --bench "$bench" -- --noplot "$@"
    echo "== $bench, before ($before)"
    env "$before" cargo bench -p threshold-execution -F testing --bench "$bench" -- --noplot "$@"
done
python3 core/threshold-execution/benches/lincomb_table.py "$CRITERION_DIR"
