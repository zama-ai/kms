#!/usr/bin/env bash
#
# Byte-freeze gate for frozen reference assets, complementing the digest test
# core/service/tests/evm_path_byte_frozen.rs.
#
# The hard-failing paths below are pure frozen assets — anything that changes there changes a
# reference, not an implementation.
#
# The EVM path's own tests live in inline `#[cfg(test)]` modules inside production files, so a
# path deny-list cannot separate "edited the production code" from "edited the EVM test next to
# it". Those files are therefore *reported* for the reviewer instead of failed, and the byte-level
# guarantee for them comes from the frozen-digest test, not from this script.
#
# Usage: ci/scripts/frozen_paths.sh [base-ref]
#   base-ref defaults to $GITHUB_BASE_REF, then to main.

set -euo pipefail

BASE_REF="${1:-${GITHUB_BASE_REF:-main}}"

if ! git rev-parse --verify --quiet "${BASE_REF}" >/dev/null; then
    if git rev-parse --verify --quiet "origin/${BASE_REF}" >/dev/null; then
        BASE_REF="origin/${BASE_REF}"
    else
        echo "error: base ref '${BASE_REF}' not found; fetch it before running this check" >&2
        exit 2
    fi
fi

MERGE_BASE="$(git merge-base "${BASE_REF}" HEAD)"

# Modified or deleted only. Adding a reference (a new backward-compatibility snapshot for a new
# release) is ordinary work; changing or removing one that already exists is what breaks
# byte-compatibility, and that is what this gate refuses. Rename detection is disabled so a
# renamed-and-edited frozen asset still shows up as a deletion at the frozen path instead of an
# `R` entry that the `MD` filter would miss.
CHANGED="$(git diff --no-renames --name-only --diff-filter=MD "${MERGE_BASE}" HEAD)"

# Frozen assets: references, not implementations. Modifying one is the failure this gate exists
# for. core/grpc/proto is deliberately absent: proto changes must be additive in field numbers,
# and that rule is checked in Rust, where the wire rule actually lives.
#
# The EVM entries freeze the shipped EVM references; the Solana entries freeze the published
# linker vectors, their set digest, and the constants snapshot, which other repositories
# reproduce. Changing the hasher layout, scheme tag, or call separator is a version bump in
# `SolanaUserDecryptionLinker:v1`. Replacing the published chain-id numbers is a protocol
# decision that needs its own reviewed change. The type-byte encoding (`0x01` instead of bit 63)
# is that change. The gate diffs against the PR base, so it would refuse the replacement.
# Skip a listed path only when sha256(base) and sha256(head) are this exact pair. After merge the
# base hash is the new blob, so later edits fail as usual.
FROZEN_GLOBS=(
    'backward-compatibility/data/*'
    'backward-compatibility/generate-*/*'
    'core/service/tests/evm_path_byte_frozen.rs'
    'core/grpc/test-vectors/solana_linker_v1.json'
    'core/grpc/test-vectors/solana_linker_v1.sha256'
    'core/grpc/tests/solana_frozen_constants.rs'
)

# path:sha256(merge-base blob):sha256(head file)
TYPE_BYTE_REPUBLISH=(
    'core/grpc/test-vectors/solana_linker_v1.json:7c0297629ca4f465459065810f5b1c72f721376aa7ee25fd8ab84d703164f513:f93384ed57c16d6fcc6aa08d2a42ea86fcc1c95bb0d25792fe62edb0b2562c52'
    'core/grpc/test-vectors/solana_linker_v1.sha256:0e0de0a37d6fc243c89b7e2c27acbe296d75c69cc10c949c6d3b9bcfc7d6552a:3c225ea33dfb034974a357c570252bb4f8991da9ce9bcd45a1a1d701a66ab104'
    'core/grpc/tests/solana_frozen_constants.rs:2f4984397255923c68f9a1dc044b1e29181a520eaadc9fe5676dcb42380433e7:700913621825be00fa569d050abbbfde86b7a5d8181424dba597eb0c731b6be0'
    'core/service/tests/evm_path_byte_frozen.rs:d3ea310a57d53105ec57079be690b9181cae4b843f304dea8030d68978839722:7d54e584caf58789a8fcae01a7fe20558a643a96fa3abcccd2adaa2a77c18dfd'
)

content_sha256() {
    openssl dgst -sha256 "$1" | awk '{print $NF}'
}

blob_sha256() {
    git cat-file blob "$1" | openssl dgst -sha256 | awk '{print $NF}'
}

is_type_byte_republish() {
    local file="$1"
    local entry path rest base_hash head_hash actual_base actual_head
    for entry in "${TYPE_BYTE_REPUBLISH[@]}"; do
        path="${entry%%:*}"
        rest="${entry#*:}"
        base_hash="${rest%%:*}"
        head_hash="${rest#*:}"
        [ "${file}" = "${path}" ] || continue
        actual_base="$(blob_sha256 "${MERGE_BASE}:${path}")"
        actual_head="$(content_sha256 "${path}")"
        if [ "${actual_base}" = "${base_hash}" ] && [ "${actual_head}" = "${head_hash}" ]; then
            echo "Byte-freeze gate: allowing type-byte republish of ${path}."
            return 0
        fi
        return 1
    done
    return 1
}

violations=()
while IFS= read -r file; do
    [ -n "${file}" ] || continue
    for glob in "${FROZEN_GLOBS[@]}"; do
        # shellcheck disable=SC2053 # glob matching is the point
        if [[ ${file} == ${glob} ]]; then
            if is_type_byte_republish "${file}"; then
                continue
            fi
            violations+=("${file}")
        fi
    done
done <<<"${CHANGED}"

if [ ${#violations[@]} -ne 0 ]; then
    echo "Byte-freeze gate FAILED — frozen assets modified against ${BASE_REF}:" >&2
    printf '  %s\n' "${violations[@]}" >&2
    echo >&2
    echo "These paths hold frozen references. If a reference genuinely must move, that is a" >&2
    echo "protocol decision and needs its own reviewed change, not a line in this series." >&2
    exit 1
fi

echo "Byte-freeze gate: no frozen asset modified against ${BASE_REF}."

# Report-only half: files that mix production code with inline tests.
mixed=()
while IFS= read -r file; do
    [ -n "${file}" ] || continue
    case "${file}" in
    *.rs) ;;
    *) continue ;;
    esac
    [ -f "${file}" ] || continue
    if grep -q '#\[cfg(test)\]' "${file}"; then
        mixed+=("${file}")
    fi
done <<<"${CHANGED}"

if [ ${#mixed[@]} -ne 0 ]; then
    echo
    echo "Reviewer note — these changed files carry inline tests. Confirm that no pre-existing"
    echo "EVM test was edited to accommodate new behaviour (added Solana tests are expected):"
    printf '  %s\n' "${mixed[@]}"
fi
