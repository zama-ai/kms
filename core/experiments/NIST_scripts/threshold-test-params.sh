#!/bin/bash

# Campaign driver for the kms reproducible threshold benchmarks.
#
# Usage:
#   ./threshold-test-params.sh             # full run: KAT + memory benchmarks
#   ./threshold-test-params.sh --kat-only  # skip the memory section
#
# A "full" run executes, for every TFHE variant (small, large,
# small_malicious) and for BGV, both the reproducible session (KAT — hash
# assertions on keys / reshare / CRS) and a memory-instrumented twin.
# `--kat-only` runs the KAT section only — faster, no peak-allocator
# instrumentation.
#
# Each TFHE variant runs in lock-step:
#   1. spin up the cluster
#   2. run the tfhe_reproducible_<variant>.sh test_script
#   3. tear the cluster down
#   4. spin the cluster up again
#   5. run the crs_reproducible_<variant>.sh sweep
#   6. tear the cluster down
#
# Key generation, CRS, and reshare are all checked against pinned SHA-256
# hashes (see each wrapper's EXPECTED_*_HASH / EXPECTED_CRS_HASHES table)
# so a drift in any of those phases fails the campaign loudly.
#
# At the end the per-run subfolders under temp/session_stats/campaign_<TS>/
# are passed to session-stats-parser.py, which emits seven CSVs into
# core/experiments/NIST_scripts/threshold/ tagged with "TestParams".

set -e

# Fleet identity tags recorded in every BENCH_PARAMS.txt this campaign
# produces. These populate the REGIONS / MACHINE_TYPE columns in the
# CSVs so a "TestParams" campaign is visibly distinguishable from a
# real EC2 campaign (whose bench_nist wrappers set REGIONS to the AWS
# region summary and MACHINE_TYPE to the instance class). The
# reproducible test_scripts default these to the same values via
# ``${REGIONS:-local}`` / ``${MACHINE_TYPE:-Baseline}`` for standalone
# invocations; exporting them here just makes the choice explicit for
# anyone reading this campaign driver.
export REGIONS=local
export MACHINE_TYPE=Baseline

# --- CLI -------------------------------------------------------------------
MODE="all"
if [ "${1:-}" = "--kat-only" ]; then
    MODE="kat-only"
elif [ -n "${1:-}" ]; then
    echo "Usage: $0 [--kat-only]" >&2
    exit 2
fi

# --- Path setup ------------------------------------------------------------
# Scripts are in test_scripts folder; this script lives in NIST_scripts/.
PATH_TO_HERE="$(cd "$(dirname "$0")" && pwd)"
PATH_TO_ROOT="$PATH_TO_HERE/.."
cd "$PATH_TO_ROOT"

# Campaign folder collects this invocation's per-run subfolders. Each
# subfolder is created by a single test_script call and holds the
# session_stats_<i>.txt files moved in by that script's EXIT trap plus the
# BENCH_PARAMS.txt the script wrote. The parser at the end consumes the
# campaign folder and emits one CSV set for this invocation.
CAMPAIGN_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN_DIR="temp/session_stats/campaign_${CAMPAIGN_DATE}"
mkdir -p "$CAMPAIGN_DIR"

# --- Helpers ---------------------------------------------------------------
# Stop + remove docker containers for a specific compose file. Safe to call
# when the file doesn't exist (no-op).
function cleanup_docker {
    local compose_file="$1"
    if [ -z "$compose_file" ]; then
        echo "cleanup_docker requires a docker-compose file path"
        return 1
    fi
    if [ ! -f "$compose_file" ]; then
        return 0
    fi
    echo "Cleaning up docker containers for $compose_file..."
    docker compose --progress=quiet -f "$compose_file" down --remove-orphans
}

# Run a test_script that takes a "GEN" positional arg (the
# tfhe_reproducible_* and bgv_reproducible scripts), with RUN_DEST pointed
# at a fresh per-run subfolder under the campaign folder.
function run_in_campaign {
    local script="$1"
    local conf="$2"
    local extra="${3:-}"
    local experiment run_date
    experiment="$(basename "$conf" .toml)"
    run_date="$(date -u +%Y%m%dT%H%M%SZ)"
    export RUN_DEST="$CAMPAIGN_DIR/${experiment}_${run_date}"
    if [ -n "$extra" ]; then
        env $extra "$script" "$conf" GEN
    else
        "$script" "$conf" GEN
    fi
    unset RUN_DEST
}

# Like run_in_campaign but for the crs_reproducible_* wrappers (no "GEN"
# arg). Per-run folder name gets a `_crs` suffix so it doesn't shadow the
# matching tfhe_reproducible_* run on the same .toml.
function run_crs_in_campaign {
    local script="$1"
    local conf="$2"
    local experiment run_date
    experiment="$(basename "$conf" .toml)"
    run_date="$(date -u +%Y%m%dT%H%M%SZ)"
    export RUN_DEST="$CAMPAIGN_DIR/${experiment}_crs_${run_date}"
    "$script" "$conf"
    unset RUN_DEST
}

# Run one TFHE variant end-to-end: cluster-up, reproducible session,
# cluster-down, cluster-up, CRS sweep, cluster-down. The cluster lifecycle
# pattern matches what each test_script expects (single use per cluster).
#
# Args:
#   $1 cluster_base  — base name used for both the cargo-make target and
#                       the docker-compose .yml file, e.g.
#                       "tfhe-bench-run-4p". When with_mem=1 the cargo
#                       target gets `-mem` appended (so the right docker
#                       image is loaded); the .yml filename stays bare,
#                       matching the existing convention.
#   $2 repro_script  — test_scripts/<this>.sh, the tfhe_reproducible_*
#                       wrapper for this variant
#   $3 crs_script    — test_scripts/<this>.sh, the crs_reproducible_*
#                       wrapper for this variant
#   $4 with_mem      — 0 (regular) or 1 (memory bench: appends -mem to
#                       the cargo target + .toml; forces NUM_CTXTS=1 on
#                       the reproducible session)
function run_tfhe_variant {
    local cluster_base="$1"
    local repro_script="$2"
    local crs_script="$3"
    local with_mem="$4"

    local target="$cluster_base"
    local toml="temp/${cluster_base}.toml"
    local extra=""
    if [ "$with_mem" = "1" ]; then
        target="${cluster_base}-mem"
        toml="temp/${cluster_base}-mem.toml"
        extra="NUM_CTXTS=1"
    fi
    local yml="temp/${cluster_base}.yml"

    # Reproducible session
    cargo make "$target"
    run_in_campaign "./test_scripts/${repro_script}" "$toml" "$extra"
    cleanup_docker "$yml"

    # CRS sweep on the same topology — fresh cluster so the test_script
    # contract (single use) holds.
    cargo make "$target"
    run_crs_in_campaign "./test_scripts/${crs_script}" "$toml"
    cleanup_docker "$yml"
}

# Run the BGV variant. Simpler than TFHE — no CRS sweep, just the
# reproducible session.
#
# Args:
#   $1 with_mem — 0 or 1.
function run_bgv_variant {
    local with_mem="$1"

    local target="bgv-bench-run"
    local toml="temp/bgv-bench-run.toml"
    local extra=""
    if [ "$with_mem" = "1" ]; then
        target="bgv-bench-run-mem"
        toml="temp/bgv-bench-run-mem.toml"
        extra="NUM_CTXTS=1"
    fi

    cargo make "$target"
    run_in_campaign ./test_scripts/bgv_reproducible.sh "$toml" "$extra"
    cleanup_docker "temp/bgv-bench-run.yml"
}

# --- Pre-cleanup -----------------------------------------------------------
# Leftover containers from a previous (possibly aborted) campaign would
# wedge our cluster bring-up. Drop anything we might want to spin up.
cleanup_docker "temp/tfhe-bench-run-4p.yml"
cleanup_docker "temp/tfhe-bench-run-5p.yml"
cleanup_docker "temp/tfhe-bench-run-4p-malicious-drop.yml"
cleanup_docker "temp/bgv-bench-run.yml"

# --- KAT section: hash-checked reproducible runs ---------------------------
### TFHE
cargo make tfhe-docker-image-degree-3
run_tfhe_variant \
    tfhe-bench-run-4p \
    tfhe_reproducible_small_session.sh \
    crs_reproducible_small_session.sh \
    0
run_tfhe_variant \
    tfhe-bench-run-5p \
    tfhe_reproducible_large_session.sh \
    crs_reproducible_large_session.sh \
    0
run_tfhe_variant \
    tfhe-bench-run-4p-malicious-drop \
    tfhe_reproducible_small_session_malicious.sh \
    crs_reproducible_small_session_malicious.sh \
    0

### BGV
cargo make bgv-docker-image
run_bgv_variant 0

# --- Memory section --------------------------------------------------------
if [ "$MODE" = "all" ]; then
    ### TFHE
    cargo make tfhe-docker-image-degree-3-mem
    run_tfhe_variant \
        tfhe-bench-run-4p \
        tfhe_reproducible_small_session.sh \
        crs_reproducible_small_session.sh \
        1
    run_tfhe_variant \
        tfhe-bench-run-5p \
        tfhe_reproducible_large_session.sh \
        crs_reproducible_large_session.sh \
        1

    ### BGV
    cargo make bgv-docker-image-mem
    run_bgv_variant 1
fi

# --- Parser ----------------------------------------------------------------
# Aggregate every per-run subfolder under the campaign folder into one
# CSV set tagged "TestParams" under NIST_scripts/threshold/. The parser
# pairs mem twins to their non-mem siblings (by the `-mem` suffix on
# EXPERIMENT_NAME) so memory cells land in the same rows.
python3 "$PATH_TO_HERE/session-stats-parser.py" --output-dir "$PATH_TO_HERE/threshold" "$PATH_TO_ROOT/$CAMPAIGN_DIR" TestParams
