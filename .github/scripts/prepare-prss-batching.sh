#!/usr/bin/env bash
# TEMP: REMOVE BEFORE MERGE. Prepare isolated, inspectable sources for the batching comparison.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
output=${1:?Usage: prepare-prss-batching.sh ABSOLUTE_OUTPUT_DIRECTORY [all|group16|accumulate|refactor|main|full]}
comparison=${2:-all}
[[ "$output" = /* ]] || { echo 'Output must be an absolute path' >&2; exit 1; }
mkdir -p "$(dirname "$output")"
mkdir "$output"
mkdir "$output/sources"
scalar_ref=d4ec6790c54eb5b9488ab5c01e6712f4e7a608c6
git cat-file -e "$scalar_ref^{commit}"
git rev-parse HEAD > "$output/commit.txt"
git diff HEAD -- core/threshold-execution core/threshold-algebra > "$output/working-source.patch"
printf '%s\n' "$scalar_ref" > "$output/scalar-commit.txt"

case "$comparison" in
    group16) variants=(group8-word group16-word) ;;
    # Array-returning PRF groups from a fixed commit against in-place accumulation from the checkout.
    accumulate) variants=(group8-word group16-word group8-acc group16-acc) ;;
    # Local only: the uncommitted accumulate snapshot against the checkout's infallible, degree-sized kernels.
    refactor) variants=(group8-acc group16-acc group8-new group16-new) ;;
    # Current main against this branch's group-16 kernels.
    main) variants=(main group16-new) ;;
    # PR evidence: main, #894 alone (scalar), and this branch with groups of 8 and 16.
    full) variants=(main scalar group8-new group16-new) ;;
    all)
        variants=(scalar group2 group4 group8 scalar-word group8-word group16-word)
        case "$(uname -m)" in
            arm64|aarch64) variants+=(group8-neon) ;;
            *) printf '%s\n' 'NEON candidate skipped: this host is not ARM; group8-word measures the portable path.' \
                > "$output/neon-skipped.txt" ;;
        esac
        ;;
    *) echo "Unknown comparison: $comparison" >&2; exit 1 ;;
esac
printf '%s\n' "${variants[@]}" > "$output/variants.txt"
printf '%s\n' "$comparison" > "$output/comparison.txt"
original_group_ref=$(git rev-parse 36bb8f3a7)
printf '%s\n' "$original_group_ref" > "$output/original-group-commit.txt"
# Last commit whose grouped PRFs return arrays. The accumulate comparison uses it for its -word baselines.
word_ref=3ea76bb448b765e07bf61585be02d89128e4efe2
# Local `git stash create` snapshot of the first in-place accumulation. It exists only in the maintainer's checkout.
acc_ref=192a80aef7980f0b829f337064ade5ef45c70ecf
# main when the comparison was prepared; its PRSS sources and Cargo.lock match this branch's merge base.
main_ref=d09406212e1a0d510436eef665ee197d0c1b1788

for variant in "${variants[@]}"; do
    source_dir="$output/sources/$variant"
    mkdir "$source_dir"
    if [[ "$variant" = main ]]; then
        git cat-file -e "$main_ref^{commit}"
        printf '%s\n' "$main_ref" > "$output/main-commit.txt"
        git archive "$main_ref" | tar -xf - -C "$source_dir"
    elif [[ "$variant" = scalar || "$variant" = scalar-word ]]; then
        git archive "$scalar_ref" | tar -xf - -C "$source_dir"
    else
        git archive HEAD | tar -xf - -C "$source_dir"
        # Copy the actual checkout files too, so a local preparation check includes uncommitted source edits.
        for path in core/threshold-algebra/src/galois_rings/common.rs core/threshold-algebra/src/lib.rs \
            core/threshold-execution/src/small_execution/prf.rs core/threshold-execution/src/small_execution/prss.rs; do
            cp "$repo_root/$path" "$source_dir/$path"
        done
        prf="$source_dir/core/threshold-execution/src/small_execution/prf.rs"
        case "$variant" in
            *-word)
                if [[ "$comparison" = accumulate ]]; then
                    # Baselines keep the array-returning PRF groups, independently of later commits.
                    git cat-file -e "$word_ref^{commit}"
                    printf '%s\n' "$word_ref" > "$output/word-commit.txt"
                    for path in core/threshold-algebra/src/galois_rings/common.rs core/threshold-algebra/src/lib.rs \
                        core/threshold-execution/src/small_execution/prf.rs core/threshold-execution/src/small_execution/prss.rs; do
                        git show "$word_ref:$path" > "$source_dir/$path"
                    done
                    if grep -q 'fn accumulate_psi_counters' "$prf"; then
                        echo "Baseline $word_ref already accumulates in place" >&2
                        exit 1
                    fi
                fi
                # Otherwise portable candidates use the current checkout, including uncommitted source changes.
                grep -q '^fn write_block(' "$prf"
                ;;
            *-acc)
                if [[ "$comparison" = refactor ]]; then
                    git cat-file -e "$acc_ref^{commit}"
                    printf '%s\n' "$acc_ref" > "$output/acc-commit.txt"
                    for path in core/threshold-algebra/src/galois_rings/common.rs core/threshold-algebra/src/lib.rs \
                        core/threshold-execution/src/small_execution/prf.rs core/threshold-execution/src/small_execution/prss.rs; do
                        git show "$acc_ref:$path" > "$source_dir/$path"
                    done
                fi
                # Otherwise in-place accumulation from the current checkout, including uncommitted source changes.
                grep -q 'fn accumulate_psi_counters' "$prf"
                grep -q 'fn accumulate_chi_counters' "$prf"
                ;;
            *-new)
                # The checkout's kernels, including uncommitted source changes.
                grep -q '^fn check_counter_range\|^pub(crate) fn check_counter_range' "$prf"
                ;;
            *) git show "$original_group_ref:core/threshold-execution/src/small_execution/prf.rs" > "$prf" ;;
        esac
        group=${variant#group}
        group=${group%%-*}
        case "$group" in
            2) group_word=two ;;
            4) group_word=four ;;
            8) group_word=eight ;;
            16) group_word=sixteen ;;
            *) echo "Unsupported counter group: $group" >&2; exit 1 ;;
        esac
        prss="$source_dir/core/threshold-execution/src/small_execution/prss.rs"
        if grep -q '^const PRF_COUNTER_GROUP: usize = 8;$' "$prss"; then
            # Current kernels take their group size from one constant.
            [[ $(grep -c '^const PRF_COUNTER_GROUP: usize = 8;$' "$prss") = 1 ]]
            sed -E "s/^const PRF_COUNTER_GROUP: usize = 8;$/const PRF_COUNTER_GROUP: usize = $group;/" "$prss" > "$prss.tmp"
            mv "$prss.tmp" "$prss"
        else
            # Older kernels: restrict substitutions to the two kernels. Fail if their expected group-eight shape has changed.
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
    fi
    # Candidates are applied only to these source copies. Original controls keep their original block writers.
    candidate_patch=
    case "$variant" in
        scalar-word) candidate_patch='scalar-word' ;;
        group8-neon) candidate_patch='group-neon' ;;
    esac
    if [[ -n "$candidate_patch" ]]; then
        patch --batch --forward --fuzz=0 -p1 -d "$source_dir" \
            < "$repo_root/.github/benchmarks/prss-patches/$candidate_patch.patch" \
            > "$output/$variant-patch.log"
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
    harness="$source_dir/core/threshold-execution/benches/prss_batching.rs"
    cp "$repo_root/.github/benchmarks/prss_batching.rs" "$harness"
    if [[ "$variant" = main ]]; then
        # main predates the role-checked session constructor; this is the harness's only API difference.
        # The single quotes keep the harness's macro variables literal.
        # shellcheck disable=SC2016
        [[ $(grep -c 'new_prss_session_state(\$sid, \$role).unwrap()' "$harness") = 1 ]]
        # shellcheck disable=SC2016
        sed -i.bak 's/new_prss_session_state(\$sid, \$role).unwrap()/new_prss_session_state($sid)/' "$harness"
        rm "$harness.bak"
    fi
done
