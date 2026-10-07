#!/usr/bin/env bash
# TEMP: REMOVE BEFORE MERGE. Prepare isolated, inspectable sources for the batching comparison.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
output=${1:?Usage: prepare-prss-batching.sh ABSOLUTE_OUTPUT_DIRECTORY}
[[ "$output" = /* ]] || { echo 'Output must be an absolute path' >&2; exit 1; }
mkdir "$output"
mkdir "$output/sources"
scalar_ref=d4ec6790c54eb5b9488ab5c01e6712f4e7a608c6
git cat-file -e "$scalar_ref^{commit}"
git rev-parse HEAD > "$output/commit.txt"
git diff HEAD -- core/threshold-execution core/threshold-algebra > "$output/working-source.patch"
printf '%s\n' "$scalar_ref" > "$output/scalar-commit.txt"

for variant in scalar group2 group4 group8; do
    source_dir="$output/sources/$variant"
    mkdir "$source_dir"
    if [[ "$variant" = scalar ]]; then
        git archive "$scalar_ref" | tar -xf - -C "$source_dir"
    else
        git archive HEAD | tar -xf - -C "$source_dir"
        # Copy the actual checkout files too, so a local preparation check includes uncommitted source edits.
        for path in core/threshold-algebra/src/galois_rings/common.rs core/threshold-algebra/src/lib.rs \
            core/threshold-execution/src/small_execution/prf.rs core/threshold-execution/src/small_execution/prss.rs; do
            cp "$repo_root/$path" "$source_dir/$path"
        done
        group=${variant#group}
        case "$group" in
            2) group_word=two ;;
            4) group_word=four ;;
            8) group_word=eight ;;
        esac
        prss="$source_dir/core/threshold-execution/src/small_execution/prss.rs"
        # Restrict substitutions to the two kernels. Fail if their expected group-eight shape has changed.
        kernel=$(sed -n '/^fn compute_prss</,/^#\[async_trait\]/p' "$prss")
        [[ $(grep -c 'amount.div_ceil(8)' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'PRSS_GEN_PAR_MIN_CHUNK).div_ceil(8)' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'let idx = group \* 8;' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'let count = (amount - idx).min(8);' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'Result<\[Z; 8\]>' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'let mut sums = \[Z::ZERO; 8\];' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'if count == 8' <<< "$kernel") = 2 ]]
        [[ $(grep -c 'counters::<Z, 8>' <<< "$kernel") = 2 ]]
        sed -E "/^fn compute_prss</,/^#\[async_trait\]/ {
            s/div_ceil\(8\)/div_ceil($group)/g
            s/group \* 8/group * $group/g
            s/\.min\(8\)/.min($group)/g
            s/\[Z; 8\]/[Z; $group]/g
            s/\[Z::ZERO; 8\]/[Z::ZERO; $group]/g
            s/count == 8/count == $group/g
            s/counters::<Z, 8>/counters::<Z, $group>/g
            s/Encrypt eight consecutive counters/Encrypt $group_word consecutive counters/
            s/at least 128 groups/at least $((1024 / group)) groups/
        }" "$prss" > "$prss.tmp"
        mv "$prss.tmp" "$prss"
    fi
    # All variants start with identical dependency locks. The harness adds the same Criterion dev-dependency.
    cmp "$repo_root/Cargo.lock" "$source_dir/Cargo.lock"
    manifest="$source_dir/core/threshold-execution/Cargo.toml"
    if grep -q '^criterion' "$manifest"; then
        echo "Unexpected existing Criterion dependency in $manifest" >&2
        exit 1
    fi
    awk '{ print } /^\[dev-dependencies\]$/ { print "criterion.workspace = true" }' "$manifest" > "$manifest.tmp"
    mv "$manifest.tmp" "$manifest"
    cat >> "$manifest" <<'TOML'

[[bench]]
name = "prss_batching"
harness = false
required-features = ["testing"]
TOML
    mkdir -p "$source_dir/core/threshold-execution/benches"
    cp "$repo_root/.github/benchmarks/prss_batching.rs" "$source_dir/core/threshold-execution/benches/prss_batching.rs"
done
