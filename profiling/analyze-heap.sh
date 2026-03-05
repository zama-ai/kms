#!/usr/bin/env bash
set -euo pipefail

# Analyze jemalloc heap profile dumps from KMS core nodes.
#
# Works on both Linux and macOS.
#
# Prerequisites:
#   - Install jeprof:
#       Ubuntu/Debian: apt install google-perftools
#       macOS:         brew install gperftools
#   - graphviz for SVG output:
#       Ubuntu/Debian: apt install graphviz
#       macOS:         brew install graphviz
#   - addr2line (from binutils) for symbol resolution
#
# Usage:
#   # 1. Start the profiling stack (from repo root)
#   make build-compose-heap-profiling
#   make start-compose-heap-profiling
#
#   # 2. Run your decryption workload, then dump + copy profiles
#   make dump-heap-profiles
#
#   # 3. Analyze
#   ./profiling/analyze-heap.sh ./profiling/heap-dumps/kms-server ./profiling/heap-dumps/core-1/
#
# Output (inside profiling/heap-analysis/):
#   top-leaks.txt    — text listing of largest allocation sites
#   latest.svg       — flamegraph of the latest heap snapshot
#   diff-leaks.txt   — allocation sites that GREW between first and last dump
#   diff.svg         — diff flamegraph (the most useful: shows your leaks)

BINARY="${1:?Usage: $0 <kms-server-binary> <heap-dump-dir>}"
DUMP_DIR="${2:?Usage: $0 <kms-server-binary> <heap-dump-dir>}"

# ── Find jeprof ──────────────────────────────────────────────────────────
JEPROF=""
for cmd in jeprof google-pprof pprof; do
    if command -v "$cmd" &>/dev/null; then
        JEPROF="$cmd"
        break
    fi
done

if [ -z "$JEPROF" ]; then
    echo "ERROR: jeprof not found. Install with:"
    echo "  Ubuntu/Debian: apt install google-perftools"
    echo "  macOS:         brew install gperftools"
    echo "  Or build from: https://github.com/gperftools/gperftools"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/heap-analysis"
mkdir -p "$OUT_DIR"

# ── Cross-platform helpers ────────────────────────────────────────────────
# realpath: available on Linux, but not always on macOS
portable_realpath() {
    if command -v realpath &>/dev/null; then
        realpath "$1"
    else
        # Python fallback (available on macOS by default)
        python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$1"
    fi
}

# sed -i: GNU sed uses -i (no suffix arg), BSD (macOS) sed requires -i '' (explicit empty suffix)
portable_sed_i() {
    local expr="$1"
    local file="$2"
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "$expr" "$file"
    else
        sed -i '' "$expr" "$file"
    fi
}

ABS_BINARY="$(portable_realpath "$BINARY")"
BINARY_NAME="$(basename "$BINARY")"

# Extract the binary load base address from a heap dump's MAPPED_LIBRARIES
get_binary_base() {
    grep -A9999 '^MAPPED_LIBRARIES:' "$1" 2>/dev/null \
        | grep -F "$ABS_BINARY" | grep -E "^[0-9a-f].*r.xp " \
        | head -1 | cut -d'-' -f1
}

# ── Working directory for processed heap dumps ───────────────────────────
# We create copies with the binary path in MAPPED_LIBRARIES rewritten to
# match the local binary. This is the critical fix for PIE/ASLR: jeprof
# uses the path in MAPPED_LIBRARIES to match the binary and compute the
# load offset — if the container path (/app/kms/.../kms-server) doesn't
# match the local path, jeprof can't translate addresses → ??:0.
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# ── Find maps.txt (captured from /proc/PID/maps by make dump-heap-profiles)
MAPS_FILE=""
for candidate in "$DUMP_DIR/maps.txt" "$(dirname "$DUMP_DIR")/maps.txt"; do
    if [ -f "$candidate" ]; then
        MAPS_FILE="$candidate"
        break
    fi
done

# ── Prepare a heap dump for jeprof ───────────────────────────────────────
# 1. Inject MAPPED_LIBRARIES if jemalloc didn't include it
# 2. Rewrite the binary path so jeprof can match it to the local binary
DUMP_COUNTER=0
prepare_dump() {
    local src="$1"
    local dst="$WORK_DIR/${DUMP_COUNTER}.heap"
    DUMP_COUNTER=$((DUMP_COUNTER + 1))
    cp "$src" "$dst"

    # Inject MAPPED_LIBRARIES from maps.txt if the dump doesn't have it
    if [ -n "$MAPS_FILE" ] && ! grep -q '^MAPPED_LIBRARIES:' "$dst" 2>/dev/null; then
        echo "  Injecting MAPPED_LIBRARIES into $(basename "$src")"
        printf '\nMAPPED_LIBRARIES:\n' >> "$dst"
        cat "$MAPS_FILE" >> "$dst"
    fi

    # Rewrite the binary path in MAPPED_LIBRARIES so jeprof can match it.
    # Container path: /app/kms/core/service/bin/kms-server
    # Local path:     /home/user/.../profiling/heap-dumps/kms-server
    if grep -q 'MAPPED_LIBRARIES:' "$dst" 2>/dev/null; then
        portable_sed_i "s|[^ ]*/${BINARY_NAME}\$|${ABS_BINARY}|" "$dst"
    fi

    echo "$dst"
}

# ── Find heap dumps, sorted by modification time (oldest first) ──────────
# Prepare working copies and partition manual vs auto in a single pass.
# Auto-dumps (in /auto/ subdir from prof_gdump) fire at memory peaks and can
# invert diff direction, so we prefer manual dumps (from SIGUSR1) for diffs.
ALL_ORIG=()            # all original paths
WORK_ALL=()            # all working copies
MANUAL_ORIGINALS=()    # manual-only originals
MANUAL_WORK=()         # manual-only working copies
while IFS= read -r heap; do
    work="$(prepare_dump "$heap")"
    ALL_ORIG+=("$heap")
    WORK_ALL+=("$work")
    if [[ "$heap" != *"/auto/"* ]]; then
        MANUAL_ORIGINALS+=("$heap")
        MANUAL_WORK+=("$work")
    fi
done < <(find "$DUMP_DIR" -name '*.heap' -type f -exec ls -1tr {} +)

if [ ${#ALL_ORIG[@]} -eq 0 ]; then
    echo "ERROR: No .heap files found in $DUMP_DIR"
    echo "Did you run 'make dump-heap-profiles'?"
    exit 1
fi

echo "Found ${#ALL_ORIG[@]} heap dump(s)"

if [ ${#MANUAL_WORK[@]} -ge 2 ]; then
    DUMPS_ORIG=("${MANUAL_ORIGINALS[@]}")
    DUMPS_WORK=("${MANUAL_WORK[@]}")
    echo "Using ${#MANUAL_WORK[@]} manual dump(s) for diff analysis"
else
    DUMPS_ORIG=("${ALL_ORIG[@]}")
    DUMPS_WORK=("${WORK_ALL[@]}")
fi

LATEST_ORIG="${DUMPS_ORIG[-1]}"
LATEST_WORK="${DUMPS_WORK[-1]}"

# ── 1. Top allocation sites in the latest dump ───────────────────────────
echo ""
echo "=== Top allocation sites (latest dump: $(basename "$LATEST_ORIG")) ==="
("$JEPROF" --text --lines "$BINARY" "$LATEST_WORK" || true) | head -40 | tee "$OUT_DIR/top-leaks.txt"
echo ""

# ── Fallback: manual addr2line if jeprof shows ??:0 ──────────────────────
if grep -q '??:0' "$OUT_DIR/top-leaks.txt" 2>/dev/null; then
    echo "WARNING: jeprof could not resolve symbols (??:0)."

    # Try to extract the binary base address from MAPPED_LIBRARIES
    BASE_ADDR=$(get_binary_base "$LATEST_WORK")

    if [ -n "$BASE_ADDR" ] && command -v addr2line &>/dev/null; then
        echo "  Falling back to manual addr2line (binary base: 0x${BASE_ADDR})"
        echo ""
        echo "=== Manual symbol resolution ==="
        # Re-read the jeprof output and resolve each address
        grep -oE '0x[0-9a-f]+' "$OUT_DIR/top-leaks.txt" | sort -u | while read -r addr; do
            # Compute binary offset: virtual_addr - load_base
            offset=$(printf "0x%x" $(( addr - 0x${BASE_ADDR} )) 2>/dev/null) || continue
            resolved=$(addr2line -C -f -e "$BINARY" "$offset" 2>/dev/null | head -2 | tr '\n' ' ')
            if [ -n "$resolved" ] && [[ "$resolved" != *"??"* ]]; then
                printf "  %-20s → %s\n" "$addr" "$resolved"
            fi
        done | tee "$OUT_DIR/resolved-symbols.txt"
        echo ""
    else
        echo "  Checklist:"
        echo "    1. Binary has debug info?  readelf -S '$BINARY' | grep debug"
        echo "    2. addr2line installed?    which addr2line"
        if [ -z "$MAPS_FILE" ]; then
            echo "    3. No maps.txt found — re-run 'make dump-heap-profiles' to capture /proc/PID/maps"
        fi
        echo ""
    fi
fi

# ── 2. SVG of the latest dump ────────────────────────────────────────────
echo "Generating $OUT_DIR/latest.svg ..."
"$JEPROF" --svg --lines "$BINARY" "$LATEST_WORK" > "$OUT_DIR/latest.svg"
echo "  Open $OUT_DIR/latest.svg in a browser to see the full allocation flamegraph."
echo ""

# ── 3. Diff between earliest and latest dump ─────────────────────────────
if [ ${#DUMPS_WORK[@]} -ge 2 ]; then
    EARLIEST_ORIG="${DUMPS_ORIG[0]}"
    EARLIEST_WORK="${DUMPS_WORK[0]}"

    # Detect cross-run diffs: if the ASLR base addresses differ, the dumps
    # are from different process instances and the diff is meaningless.
    BASE_EARLIEST=$(get_binary_base "$EARLIEST_WORK")
    BASE_LATEST=$(get_binary_base "$LATEST_WORK")

    if [ -n "$BASE_EARLIEST" ] && [ -n "$BASE_LATEST" ] && [ "$BASE_EARLIEST" != "$BASE_LATEST" ]; then
        echo "WARNING: Dumps are from DIFFERENT process instances (ASLR bases differ)."
        echo "  earliest: 0x${BASE_EARLIEST}  ($(basename "$EARLIEST_ORIG"))"
        echo "  latest:   0x${BASE_LATEST}  ($(basename "$LATEST_ORIG"))"
        echo "  The diff below will be meaningless. Clean up and take fresh dumps:"
        echo "    rm -rf ./profiling/heap-dumps/core-*/"
        echo "    make dump-heap-profiles   # first dump"
        echo "    # ... run workload ..."
        echo "    make dump-heap-profiles   # second dump"
        echo ""
    fi

    echo "=== Diff: $(basename "$EARLIEST_ORIG") → $(basename "$LATEST_ORIG") ==="
    echo "  (Shows allocations that GREW — i.e., your leaks)"
    echo ""
    ("$JEPROF" --text --lines --base="$EARLIEST_WORK" "$BINARY" "$LATEST_WORK" || true) | head -40 | tee "$OUT_DIR/diff-leaks.txt"
    echo ""

    echo "Generating $OUT_DIR/diff.svg ..."
    "$JEPROF" --svg --lines --base="$EARLIEST_WORK" "$BINARY" "$LATEST_WORK" > "$OUT_DIR/diff.svg"
    echo "  Open $OUT_DIR/diff.svg — this is the MOST USEFUL output."
    echo "  It shows only the allocations that grew between the two dumps."
    echo ""
else
    echo "Only 1 dump found. For diff analysis, take at least 2 manual dumps:"
    echo "  make dump-heap-profiles   # before load"
    echo "  # ... run your workload ..."
    echo "  make dump-heap-profiles   # after load"
    echo ""
fi

echo "=== Analysis complete ==="
echo "Files in $OUT_DIR/:"
ls -lh "$OUT_DIR/"
