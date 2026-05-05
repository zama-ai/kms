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
# We note that the key generation and the CRS and resahre (when applicable) are checked against a
# known hash to ensure they were done correctly.
#
# At the end of the scripts, the timing resulsts are parsed and put in the threshold folder with the tag "TestParams".
# We do not perform a memory benchmark on top of these tests as memory benchmark are much slower.

# Function to stop and rm docker containers if any is still running
function cleanup_docker {
    if [ "$(docker ps -a -q)" ]; then
        echo "Cleaning up docker containers..."
        docker stop $(docker ps -a -q) && docker rm $(docker ps -a -q)
    fi
}

# Scripts are in test_scripts folder
PATH_TO_HERE="$(cd "$(dirname "$0")" && pwd)"
PATH_TO_ROOT="$PATH_TO_HERE/.."
PATH_TO_SCRIPTS="$PATH_TO_ROOT/test_scripts"

echo "Running reproducible tests. Will look for scripts in $PATH_TO_SCRIPTS"

# Set current workdirectory as root of experiments
cd "$PATH_TO_ROOT"

# Start with cleaning up all docker things
cleanup_docker

### TFHE
# Prepare the tfhe docker image
cargo make tfhe-docker-image-degree-3

## small session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-4p
# Run the test script
./$PATH_TO_SCRIPTS/tfhe_reproducible_small_session.sh temp/tfhe-bench-run-4p.toml GEN
# Teardown docker
cleanup_docker

## large session
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-5p
# Run the test script
./$PATH_TO_SCRIPTS/tfhe_reproducible_large_session.sh temp/tfhe-bench-run-5p.toml GEN
# Teardown docker
cleanup_docker

## small session with malicious party
# Create the test setup and starts the docker containers
cargo make tfhe-bench-run-4p-malicious-bcast
# Run the test script
./$PATH_TO_SCRIPTS/tfhe_reproducible_small_session_malicious.sh temp/tfhe-bench-run-4p-malicious-bcast.toml GEN
# Teardown docker
cleanup_docker

### BGV
# Prepare the bgv docker image
cargo make bgv-docker-image

# Create the test setup and starts the docker containers
cargo make bgv-bench-run
# Run the test script
./$PATH_TO_SCRIPTS/bgv_reproducible.sh temp/bgv-bench-run.toml GEN
# Teardown docker
cleanup_docker


### Run stats parser
python3 "$PATH_TO_HERE/session_parser.py --output-dir $PATH_TO_HERE/threshold $PATH_TO_ROOT/temp/session_stats TestParams"



