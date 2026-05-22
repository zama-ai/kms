#!/bin/bash

# A script that runs the reproducible tests (i.e. fixed seed) for
# - tfhe-rs with small sessions (4 parties, threshold 1) with test parameters
# - tfhe-rs with large sessions (5 parties, threshold 1) with test parameters
# - tfhe-rs with small sessions and 1 malicious party (4 parties, threshold 1) with test parameters
# - BGV (4 parties, threshold 1) with real parameters
# Each of these tests runs :
# - Necessary PRSS init(s) (except for large sessions)
# - A preprocessing phase for the DKG
# - The DKG
# - (For tfhe only) a CRS gen
# - (For tfhe only) a resharing of the key generated during DKG
# - A bunch of decryptons
#
# We note that the key generation and the CRS and reshare (when applicable) are checked against a
# known hash to ensure they were done correctly.
#
# At the end of the scripts, the timing resulsts are parsed and put in the threshold folder with the tag "TestParams".
# We do not perform a memory benchmark on top of these tests as memory benchmark are much slower.

# Function to stop and remove docker containers for a specific compose file
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

# Scripts are in test_scripts folder
PATH_TO_HERE="$(cd "$(dirname "$0")" && pwd)"
PATH_TO_ROOT="$PATH_TO_HERE/.."

# Set current workdirectory as root of experiments
cd "$PATH_TO_ROOT"

# Create a campaign folder that collects this invocation's per-run subfolders
# (one per test_script call). Each per-run subfolder will end up holding the
# session_stats_<i>.txt files moved in by the test_script's EXIT trap plus
# the BENCH_PARAMS.txt the test_script wrote. The parser is invoked at the
# end on the campaign folder to produce a single CSV set for this campaign.
CAMPAIGN_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN_DIR="temp/session_stats/campaign_${CAMPAIGN_DATE}"
mkdir -p "$CAMPAIGN_DIR"
# Helper that runs a test_script with RUN_DEST pointed at a fresh per-run
# subfolder under the campaign folder. The folder name embeds the
# experiment_name (basename of the .toml) and a UTC timestamp.
function run_in_campaign {
    local script="$1"
    local conf="$2"
    local extra="${3:-}"
    local experiment
    experiment="$(basename "$conf" .toml)"
    local run_date
    run_date="$(date -u +%Y%m%dT%H%M%SZ)"
    export RUN_DEST="$CAMPAIGN_DIR/${experiment}_${run_date}"
    if [ -n "$extra" ]; then
        env $extra "$script" "$conf" GEN
    else
        "$script" "$conf" GEN
    fi
    unset RUN_DEST
}

# Start with cleaning up any leftover containers for the targeted benchmark compose files
cleanup_docker "temp/tfhe-bench-run-4p.yml"
cleanup_docker "temp/tfhe-bench-run-5p.yml"
cleanup_docker "temp/tfhe-bench-run-4p-malicious-bcast.yml"
cleanup_docker "temp/bgv-bench-run.yml"

### All but memory benchmarks
### TFHE
# Prepare the tfhe docker image
cargo make tfhe-docker-image-degree-3

## small session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-4p
# Run the test script
run_in_campaign ./test_scripts/tfhe_reproducible_small_session.sh temp/tfhe-bench-run-4p.toml
# Teardown docker
cleanup_docker "temp/tfhe-bench-run-4p.yml"

## large session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-5p
# Run the test script
run_in_campaign ./test_scripts/tfhe_reproducible_large_session.sh temp/tfhe-bench-run-5p.toml
# Teardown docker
cleanup_docker "temp/tfhe-bench-run-5p.yml"

## small session with malicious party
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-4p-malicious-bcast
# Run the test script
run_in_campaign ./test_scripts/tfhe_reproducible_small_session_malicious.sh temp/tfhe-bench-run-4p-malicious-bcast.toml
# Teardown docker
cleanup_docker "temp/tfhe-bench-run-4p-malicious-bcast.yml"

### BGV
# Prepare the bgv docker image
cargo make bgv-docker-image

# Create the test setup and starts the docker containers
cargo make bgv-bench-run
# Run the test script
run_in_campaign ./test_scripts/bgv_reproducible.sh temp/bgv-bench-run.toml
# Teardown docker
cleanup_docker "temp/bgv-bench-run.yml"


### Memory benchmarks
### TFHE
# Prepare the tfhe docker image
cargo make tfhe-docker-image-degree-3-mem

## small session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-4p-mem
# Run the test script
run_in_campaign ./test_scripts/tfhe_reproducible_small_session.sh temp/tfhe-bench-run-4p-mem.toml "NUM_CTXTS=1"
# Teardown docker
cleanup_docker "temp/tfhe-bench-run-4p.yml"

## large session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-5p-mem
# Run the test script
run_in_campaign ./test_scripts/tfhe_reproducible_large_session.sh temp/tfhe-bench-run-5p-mem.toml "NUM_CTXTS=1"
# Teardown docker
cleanup_docker "temp/tfhe-bench-run-5p.yml"

### BGV
# Prepare the bgv docker image
cargo make bgv-docker-image-mem

# Create the test setup and starts the docker containers
cargo make bgv-bench-run-mem
# Run the test script
run_in_campaign ./test_scripts/bgv_reproducible.sh temp/bgv-bench-run-mem.toml "NUM_CTXTS=1"
# Teardown docker
cleanup_docker "temp/bgv-bench-run.yml"


### Run stats parser
# Point the parser at this campaign's folder so the CSVs reflect just this
# invocation. The campaign folder contains one subfolder per test_script call;
# each subfolder has BENCH_PARAMS.txt + session_stats_<i>.txt and is enough
# for the parser to build a row per (run, ciphertext_type/parallelism).
python3 "$PATH_TO_HERE/session-stats-parser.py" --output-dir "$PATH_TO_HERE/threshold" "$PATH_TO_ROOT/$CAMPAIGN_DIR" TestParams



