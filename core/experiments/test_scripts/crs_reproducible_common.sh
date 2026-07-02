#!/usr/bin/env bash
# Common logic for crs_reproducible_*.sh wrappers. Each wrapper sets the
# variant-specific knobs below and then sources this file; the body sweeps
# `mobygo crs-gen` over the wrapper's CRS_PARAMS_LIST against the cluster
# pointed to by $1 (the choreographer .toml).
#
# Wrappers must set:
#   VARIANT            — folder-name + EXPERIMENT_NAME suffix
#                        (e.g. "small", "large", "small_malicious"); used
#                        to disambiguate per-run folders when multiple
#                        variants share a .toml basename
#   NUM_PARTIES, THRESHOLD
#                      — cluster identity, recorded in BENCH_PARAMS.txt
#   MALICIOUS          — 0 / 1; recorded in BENCH_PARAMS.txt
#   SEED               — initial seed; bumped by 1 per iteration
#   CRS_PARAMS_LIST    — bash array of param-set names to sweep, e.g.
#                          CRS_PARAMS_LIST=("params-test-bk-sns" "bc-params-sns")
#   EXPECTED_CRS_HASHES — bash associative array mapping param-set name to
#                        the SHA-256 of the produced crs.bin
#                          declare -A EXPECTED_CRS_HASHES=(
#                              ["params-test-bk-sns"]="<sha256>"
#                              ["bc-params-sns"]="<sha256>"
#                          )
#
# Each iteration uses (sid, seed) = (1, $SEED), (2, $SEED+1), (3, $SEED+2),
# ... so reordering CRS_PARAMS_LIST invalidates the hashes — keep the two
# arrays in lock-step. The variant (small/large/malicious) affects the
# protocol path inside mobygo, so hashes also depend on which wrapper is
# the caller — keep each wrapper's EXPECTED_CRS_HASHES table independent.
#
# Optional env vars (defaults shown):
#   RUN_DEST=./temp/session_stats/<EXPERIMENT>_<UTC_TS>
#                             (the campaign driver sets this to land each
#                              run inside the campaign folder)
#
# NB: No PRSS init, no DKG, no Reshare, no DDEC. The cluster must already
# be up (e.g. `cargo make tfhe-bench-run-4p`); this script only drives the
# CRS phase. The accompanying BENCH_PARAMS.txt records HAS_PRSS_INIT=0 /
# HAS_DKG=0 / HAS_CRS=1 / HAS_RESHARE=0, plus CRS_PARAMS=<the swept list>.
# That lets the parser build a schedule of one CRS_GEN_<P> line per param.

set -e

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <choreographer.toml>" >&2
    echo "  (this is the common body; invoke through one of the" >&2
    echo "   crs_reproducible_{small,large,small_malicious}_session.sh wrappers)" >&2
    exit 2
fi

# Sanity-check the wrapper set everything we need.
: "${VARIANT:?wrapper must set VARIANT}"
: "${NUM_PARTIES:?wrapper must set NUM_PARTIES}"
: "${THRESHOLD:?wrapper must set THRESHOLD}"
: "${MALICIOUS:?wrapper must set MALICIOUS (0 or 1)}"
: "${SEED:?wrapper must set SEED}"
if [ "${#CRS_PARAMS_LIST[@]}" -eq 0 ]; then
    echo "❌ Wrapper must set CRS_PARAMS_LIST=(<p1> <p2> ...)" >&2
    exit 1
fi

# Validate up-front that every param in the sweep has a matching expected
# hash, so we abort before bringing the cluster into any half-swept state.
for P in "${CRS_PARAMS_LIST[@]}"; do
    if [ -z "${EXPECTED_CRS_HASHES[$P]:-}" ]; then
        echo "❌ Missing entry in EXPECTED_CRS_HASHES for params=${P} (expected SHA-256 of crs.bin)" >&2
        exit 1
    fi
done

# Render the sweep list into a space-separated string for logging and the
# CRS_PARAMS line in BENCH_PARAMS.txt (the parser splits on whitespace).
CRS_PARAMS_FLAT="${CRS_PARAMS_LIST[*]}"

# Detect memory bench from the .toml basename (matches the convention used
# by the other reproducible scripts: cluster .toml files for memory bench
# end in `-mem`). The `-mem` suffix has to land at the *end* of
# EXPERIMENT_NAME so the parser's `_base_experiment_name` strip-and-pair
# logic finds the non-mem twin by lopping it off; that's why we strip
# `-mem` from the .toml prefix and re-append it after the variant suffix.
TOML_BASENAME="$(basename "$1" .toml)"
MEASURE_MEMORY_FLAG=0
case "$TOML_BASENAME" in
    *-mem) MEASURE_MEMORY_FLAG=1 ;;
esac
TOML_PREFIX="${TOML_BASENAME%-mem}"
EXPERIMENT_NAME="${TOML_PREFIX}_crs_${VARIANT}"
if [ "$MEASURE_MEMORY_FLAG" -eq 1 ]; then
    EXPERIMENT_NAME="${EXPERIMENT_NAME}-mem"
fi

echo "Running CRS reproducible sweep on config file $1 (variant=${VARIANT}, measure_memory=${MEASURE_MEMORY_FLAG}) with CRS_PARAMS_LIST='${CRS_PARAMS_FLAT}'"

RUN_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DEST="${RUN_DEST:-./temp/session_stats/${EXPERIMENT_NAME}_${RUN_DATE}}"
mkdir -p "$RUN_DEST"

# Match the other reproducible scripts: sweep ./temp/session_stats/*.txt
# files into the per-run folder on any exit so the parser sees them in
# the right place even if mobygo aborts mid-run.
_move_session_stats() {
    mv ./temp/session_stats/session_stats_*.txt "$RUN_DEST/" 2>/dev/null || true
}
trap _move_session_stats EXIT

cat > "$RUN_DEST/BENCH_PARAMS.txt" <<EOF
=== ${RUN_DATE} ===
EXPERIMENT_NAME=${EXPERIMENT_NAME}
PROTOCOL=tfhe
SESSION_TYPE=
NUM_PARTIES=${NUM_PARTIES}
THRESHOLD=${THRESHOLD}
MALICIOUS=${MALICIOUS}
MEASURE_MEMORY=${MEASURE_MEMORY_FLAG}
PARAMS=
NUM_CTXTS=1
NUM_SESSIONS=1
PERCENTAGE_OFFLINE=100
DDEC_MODES=
CRS_PARAMS=${CRS_PARAMS_FLAT}
HAS_PRSS_INIT=0
HAS_DKG=0
HAS_CRS=1
HAS_RESHARE=0
REGIONS=${REGIONS:-local}
MACHINE_TYPE=${MACHINE_TYPE:-Baseline}
EOF

cargo build --bin mobygo
ROOT_DIR=$(cargo locate-project --workspace -q --message-format plain|grep -o '.*/')
MOBYGO_EXEC="${ROOT_DIR}/target/debug/mobygo"

MAIN_PATH="./temp/crs_reproducible_${VARIANT}"
mkdir -p "$MAIN_PATH"

export RUN_MODE=dev
exec 2>&1

CURR_SID=1
for P in "${CRS_PARAMS_LIST[@]}"; do
    EXPECTED_HASH="${EXPECTED_CRS_HASHES[$P]}"

    CRS_DIR="${MAIN_PATH}/${P}"
    mkdir -p "$CRS_DIR"

    echo "Generating CRS for params=${P} (sid=${CURR_SID}, seed=${SEED})"
    $MOBYGO_EXEC -c "$1" crs-gen --parameters "$P" --sid "$CURR_SID" --seed "$SEED"
    $MOBYGO_EXEC -c "$1" status-check --sid "$CURR_SID" --keep-retry true
    $MOBYGO_EXEC -c "$1" crs-gen-result --sid "$CURR_SID" --storage-path "$CRS_DIR"

    CRS_HASH=$(sha256sum "$CRS_DIR/crs.bin" | cut -d ' ' -f 1)
    if [ "$CRS_HASH" != "$EXPECTED_HASH" ]; then
        echo "❌ CRS hash for ${P} does not match expected. Got ${CRS_HASH}, expected ${EXPECTED_HASH}"
        exit 1
    fi
    echo "✅ CRS hash for ${P} matches expected: ${CRS_HASH}"

    CURR_SID=$(( CURR_SID + 1 ))
    SEED=$(( SEED + 1 ))
done

echo "CRS sweep complete (${CRS_PARAMS_FLAT}, variant=${VARIANT})."
