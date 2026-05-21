#!/usr/bin/env bash
# Run the wasm-test transcript-producer recipe for a single kms version.
#
# Args:
#   $1 (required) the kms version label (e.g. v0.13.10). Used to look up an
#                 optional producer_override entry in compat-matrix.json.
#   $2 (required) the path to the matrix version's checked-out source tree.
#                 Must contain core/service/. The "test-material/" directory
#                 the cargo tests look for will be placed at this root.
#   $3 (optional) path to compat-matrix.json. Defaults to ci/compat-matrix.json
#                 (resolved from this script's invocation dir, NOT the source
#                 tree from $2 — config lives with the workflow, not the tag).
#
# On success, leaves the two transcript files at:
#   <src>/core/service/temp/test-central-wasm-transcript.bin.8
#   <src>/core/service/temp/test-threshold-wasm-transcript.bin.8

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <version> <src-dir> [<compat-matrix.json>]" >&2
    exit 64
fi

VERSION="$1"
SRC_DIR="$(cd "$2" && pwd)"
CONFIG_PATH="${3:-ci/compat-matrix.json}"

# Default generate-test-material argv (HEAD form, flag-based). Overridable
# per-version via producer_overrides[VERSION].generate_test_material.
default_gtm_argv=(
    cargo run -p generate-test-material --
    --output ./test-material
    --verbose
    --profile insecure
    --parties 4,10
)

if [[ -f "${CONFIG_PATH}" ]]; then
    override_raw="$(jq -rc --arg v "${VERSION}" '.producer_overrides[$v].generate_test_material // null' "${CONFIG_PATH}")"
else
    override_raw="null"
fi

run_in_src() {
    (cd "${SRC_DIR}" && "$@")
}

echo "::group::compat-matrix producer: ${VERSION}"
echo "src dir: ${SRC_DIR}"

if [[ "${override_raw}" == "null" ]]; then
    echo "generate-test-material: default argv (HEAD flag form)"
    if run_in_src cargo metadata --format-version 1 --no-deps --quiet \
        | jq -e '.packages[] | select(.name == "generate-test-material")' >/dev/null; then
        run_in_src "${default_gtm_argv[@]}"
    else
        echo "generate-test-material crate not present in this workspace -- skipping (older versions self-generate inside the cargo tests)"
    fi
elif [[ "${override_raw}" == "[]" ]]; then
    echo "generate-test-material: explicit no-op per producer_overrides"
else
    mapfile -t override_argv < <(jq -r '.[]' <<<"${override_raw}")
    echo "generate-test-material: override argv: ${override_argv[*]}"
    run_in_src "${override_argv[@]}"
fi

# Run the two transcript-writing cargo tests. Names have been stable from
# v0.11.1 through HEAD. -F wasm_tests is mandatory: the write paths and the
# TestingUserDecryptionTranscript struct are gated behind that feature.
for test_name in \
    test_user_decryption_threshold_and_write_transcript \
    test_user_decryption_centralized_and_write_transcript
do
    echo "::group::cargo test ${test_name}"
    (cd "${SRC_DIR}/core/service" && cargo test "${test_name}" -F wasm_tests --lib)
    echo "::endgroup::"
done

# Sanity-check that the .bin.8 transcripts landed where test.js expects.
missing=0
for f in \
    "${SRC_DIR}/core/service/temp/test-central-wasm-transcript.bin.8" \
    "${SRC_DIR}/core/service/temp/test-threshold-wasm-transcript.bin.8"
do
    if [[ ! -s "${f}" ]]; then
        echo "missing or empty transcript: ${f}" >&2
        missing=1
    fi
done

if (( missing != 0 )); then
    echo "producer ${VERSION}: transcript files missing -- failing the job" >&2
    exit 1
fi

echo "::endgroup::"
echo "producer ${VERSION}: ok"
