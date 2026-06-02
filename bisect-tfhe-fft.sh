#!/usr/bin/env bash
#
# bisect-tfhe-fft.sh
# ==================
# Find the exact rustc change that made `tfhe-fft` codegen fall off a cliff
# between Rust 1.94 (good) and 1.96 (bad).  Linux/x86_64 ONLY — the blowup is in
# the AVX-512 path (tfhe-fft `avx512` feature -> `pulp/x86-v4`), which compiles to
# scalar no-ops on ARM, which is why it can't be reproduced on macOS/ARM.
#
# Evidence this targets (from cargo --timings, 1.94 vs 1.96):
#   tfhe-fft frontend: 1.7s -> 1.6s  (unchanged)
#   tfhe-fft codegen : 201s -> 9235s (x46 — a pure LLVM/codegen blowup)
# Everything else in the workspace was within noise.
#
# Release calendar (≈6-week cadence; nightly version = stable + 2):
#   1.94.0 stable 2026-03-05   (branch point ≈ 2026-01-22 -> last "good" nightly)
#   1.95.0 stable 2026-04-16
#   1.96.0 stable 2026-05-28   (branch point ≈ 2026-04-16 -> first "bad" nightly)
#   1.96 also bumped min LLVM to 21 — an LLVM major bump is a prime suspect for an
#   AVX-512 codegen-time cliff and would show up as a single submodule-bump PR.
#
# Strategy (three phases):
#   0. SANITY GATE  — confirm a known-good nightly builds FAST and a known-bad one
#                     builds SLOW. Abort early if the repro doesn't reproduce.
#   1. LANDSCAPE SCAN — coarse weekly walk over nightlies from 1.94 era to today.
#                     Answers BOTH "when was it introduced (nightly granularity)"
#                     AND "is it already fixed in 1.97/1.98" (non-monotonic — a
#                     single bisect can't see a later fix, so we scan first).
#   2. PR BISECT    — hand the discovered good/bad boundary to cargo-bisect-rustc,
#                     which binary-searches nightlies then CI merge commits to name
#                     the exact PR. If the scan found a later fix, also bisect that.
#
# Overnight use (the bad builds are capped by THRESHOLD_SECS so each is ~10 min,
# not 2.5 h):
#   nohup ./bisect-tfhe-fft.sh > bisect-run.log 2>&1 &
#   tail -f bisect-run.log
#
# Re-run knobs (all overridable via env), e.g.:
#   THRESHOLD_SECS=700 SCAN_STEP_DAYS=14 ./bisect-tfhe-fft.sh
#   SKIP_SCAN=1 INTRO_GOOD=2026-03-01 INTRO_BAD=2026-03-15 ./bisect-tfhe-fft.sh
#
set -uo pipefail

############################  CONFIG  ############################
TFHE_FFT_VERSION="${TFHE_FFT_VERSION:-0.10.1}"

# A build slower than this (seconds) is "bad". Good cold builds were ~260-320s on
# the cloud box; bad ones are ~9000s. 600s sits cleanly in the gap AND caps each
# bad probe at ~10 min. Bump it if your baseline cold build is slower than ~400s.
THRESHOLD_SECS="${THRESHOLD_SECS:-600}"

# Landscape scan range + granularity. Default lower bound is safely inside the
# 1.94-good era; upper bound is "today" (latest nightly ≈ 1.98).
SCAN_START="${SCAN_START:-2026-01-15}"
SCAN_END="${SCAN_END:-2026-06-01}"
SCAN_STEP_DAYS="${SCAN_STEP_DAYS:-7}"

# Sanity-gate probes: GOOD_PROBE must come out FAST, BAD_PROBE must come out SLOW.
GOOD_PROBE="${GOOD_PROBE:-2026-01-15}"   # ≈ 1.94 content
BAD_PROBE="${BAD_PROBE:-2026-04-16}"     # ≈ 1.96 branch content

# Where the throwaway repro crate and logs live (outside this repo on purpose).
REPRO_DIR="${REPRO_DIR:-$HOME/tfhe-fft-bisect-repro}"
WORK_DIR="${WORK_DIR:-$HOME/tfhe-fft-bisect}"

KEEP_TOOLCHAINS="${KEEP_TOOLCHAINS:-0}"  # 1 = don't uninstall scan toolchains
PRESERVE="${PRESERVE:-0}"                # 1 = pass --preserve to cargo-bisect-rustc
SKIP_SCAN="${SKIP_SCAN:-0}"              # 1 = skip phase 1 (use INTRO_GOOD/INTRO_BAD)
SKIP_BISECT="${SKIP_BISECT:-0}"          # 1 = scan only, no cargo-bisect-rustc
ALLOW_NON_X86="${ALLOW_NON_X86:-0}"      # 1 = run anyway off x86 (won't reproduce)

# Optional manual boundaries (used when SKIP_SCAN=1).
INTRO_GOOD="${INTRO_GOOD:-}"
INTRO_BAD="${INTRO_BAD:-}"
#################################################################

mkdir -p "$WORK_DIR"
SCAN_CSV="$WORK_DIR/scan-results.csv"

ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*"; }
die() { echo "[$(ts)] FATAL: $*" >&2; exit 1; }

############################  PREFLIGHT  ############################
preflight() {
  log "Preflight checks..."
  local arch; arch="$(uname -m)"
  if [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; then
    if [ "$ALLOW_NON_X86" = "1" ]; then
      log "WARNING: arch=$arch is NOT x86_64 — the bug will almost certainly NOT reproduce. Continuing because ALLOW_NON_X86=1."
    else
      die "arch=$arch is not x86_64. The tfhe-fft blowup is in the AVX-512 path and only reproduces on x86_64. Set ALLOW_NON_X86=1 to override."
    fi
  fi
  command -v rustup  >/dev/null || die "rustup not found. Install from https://rustup.rs"
  command -v timeout >/dev/null || die "'timeout' (GNU coreutils) not found."
  date -d "2026-01-01 + 1 day" +%F >/dev/null 2>&1 || die "GNU 'date -d' arithmetic unavailable (need coreutils date, i.e. Linux)."
  if ! command -v cargo-bisect-rustc >/dev/null && [ "$SKIP_BISECT" != "1" ]; then
    log "cargo-bisect-rustc not found — installing (cargo install cargo-bisect-rustc --locked)..."
    cargo install cargo-bisect-rustc --locked || die "failed to install cargo-bisect-rustc"
  fi
  log "Preflight OK (arch=$arch, threshold=${THRESHOLD_SECS}s)."
}

############################  REPRO CRATE  ############################
# A standalone crate whose only job is to pull in tfhe-fft with the same resolved
# features as the workspace (default => std+avx512, plus fft128 + serde) and at
# opt-level 3 / codegen-units 16 (matching how the workspace compiles deps), so a
# plain `cargo build` triggers the heavy tfhe-fft codegen unit. Empty [workspace]
# keeps it from being absorbed by any ancestor workspace; no rust-toolchain file
# so the active toolchain is whatever +toolchain / RUSTUP_TOOLCHAIN selects.
make_repro() {
  log "Creating repro crate at $REPRO_DIR (tfhe-fft =$TFHE_FFT_VERSION)"
  mkdir -p "$REPRO_DIR/src"
  cat > "$REPRO_DIR/Cargo.toml" <<EOF
[workspace]

[package]
name = "tfhe-fft-bisect-repro"
version = "0.0.0"
edition = "2021"

[dependencies]
# default already enables std + avx512 (-> pulp/x86-v4); add fft128 + serde to
# match the workspace's resolved feature set [avx512, default, fft128, serde, std].
tfhe-fft = { version = "=$TFHE_FFT_VERSION", default-features = true, features = ["fft128", "serde"] }

# Compile the dependency the way the workspace does so the codegen blowup shows up.
[profile.dev]
opt-level = 3
codegen-units = 16

[profile.dev.package."*"]
opt-level = 3
codegen-units = 16
EOF
  cat > "$REPRO_DIR/src/lib.rs" <<'EOF'
// Intentionally empty: tfhe-fft is compiled as a (heavy) dependency. We only ever
// measure how long the toolchain takes to codegen it.
EOF

  # Predicate used by cargo-bisect-rustc. cargo-bisect-rustc sets RUSTUP_TOOLCHAIN,
  # so a plain `cargo build` here uses the toolchain under test. Exit 0 = fast/good;
  # nonzero (incl. 124 = timed out = too slow) = bad. THRESHOLD_SECS/REPRO_DIR are
  # exported into the environment before cargo-bisect-rustc runs.
  cat > "$REPRO_DIR/predicate.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
cd "${REPRO_DIR:?REPRO_DIR not set}" || exit 99
cargo clean -q >/dev/null 2>&1
timeout -k 30 "${THRESHOLD_SECS:-600}" cargo build -q >/dev/null 2>&1
exit $?
EOF
  chmod +x "$REPRO_DIR/predicate.sh"
}

############################  SINGLE-NIGHTLY TEST  ############################
# Echoes one of: "GOOD <secs>" | "BAD <secs>" | "ERROR <secs> (exit N)" | "UNAVAILABLE"
test_nightly() {
  local tc="nightly-$1" start end secs code
  if ! rustup toolchain install --profile minimal "$tc" >/dev/null 2>&1; then
    echo "UNAVAILABLE"; return
  fi
  ( cd "$REPRO_DIR" && cargo +"$tc" clean -q >/dev/null 2>&1 )
  start=$(date +%s)
  ( cd "$REPRO_DIR" && timeout -k 30 "$THRESHOLD_SECS" cargo +"$tc" build -q >/dev/null 2>&1 )
  code=$?
  end=$(date +%s); secs=$((end - start))
  [ "$KEEP_TOOLCHAINS" = "1" ] || rustup toolchain uninstall "$tc" >/dev/null 2>&1
  if   [ "$code" -eq 0 ];                                   then echo "GOOD $secs"
  elif [ "$code" -eq 124 ] || [ "$secs" -ge "$THRESHOLD_SECS" ]; then echo "BAD $secs"
  else echo "ERROR $secs (exit $code)"; fi
}

############################  LOG PARSING / SHA RESOLUTION  ############################
# Pull the pinpointed commit from a cargo-bisect-rustc log. The final answer is
# printed on a "Regression in <sha-or-url>" line; a compare URL is good...bad, so
# the LAST 40-hex on those lines is the regressing commit.
extract_sha() {
  grep -iE 'regression in' "$1" 2>/dev/null | grep -oiE '[0-9a-f]{40}' | tail -n1
}

# The first-bad (or, for --regress=success, first-good) nightly date, e.g. from
# "Regression in nightly-2026-03-10".
extract_regressed_nightly() {
  grep -iE 'regression in nightly-' "$1" 2>/dev/null \
    | grep -oE 'nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -n1 | sed 's/^nightly-//'
}

# Resolve a nightly date to its rustc commit-hash (so we can force commit-level
# bisection by passing SHAs). Echoes "" if the toolchain can't be installed.
commit_sha_of_nightly() {
  local tc="nightly-$1" sha
  rustup toolchain install --profile minimal "$tc" >/dev/null 2>&1 || { echo ""; return; }
  sha="$(rustc +"$tc" --version --verbose 2>/dev/null | sed -n 's/^commit-hash: //p')"
  [ "$KEEP_TOOLCHAINS" = "1" ] || rustup toolchain uninstall "$tc" >/dev/null 2>&1
  echo "$sha"
}

############################  SANITY GATE  ############################
sanity_gate() {
  log "Sanity gate: GOOD_PROBE=$GOOD_PROBE should be FAST, BAD_PROBE=$BAD_PROBE should be SLOW (cap ${THRESHOLD_SECS}s each)."
  local g b
  g="$(test_nightly "$GOOD_PROBE")"; log "  good-probe nightly-$GOOD_PROBE -> $g"
  b="$(test_nightly "$BAD_PROBE")";  log "  bad-probe  nightly-$BAD_PROBE -> $b"
  case "$g" in GOOD*) ;; *) die "good-probe did not build fast ($g). Repro may be wrong (features/opt-level/threshold) — fix before an overnight run." ;; esac
  case "$b" in BAD*)  ;; *) die "bad-probe did not build slow ($b). The repro isn't reproducing the blowup — adjust REPRO/THRESHOLD before bisecting." ;; esac
  log "Sanity gate PASSED — good builds fast, bad builds slow. Repro is valid."
}

############################  LANDSCAPE SCAN  ############################
landscape_scan() {
  log "Landscape scan: nightly-$SCAN_START .. nightly-$SCAN_END every ${SCAN_STEP_DAYS}d"
  echo "date,result,seconds" > "$SCAN_CSV"
  local cur end_ts cur_ts res kind secs
  cur="$SCAN_START"
  end_ts=$(date -d "$SCAN_END" +%s)
  while :; do
    cur_ts=$(date -d "$cur" +%s)
    [ "$cur_ts" -gt "$end_ts" ] && break
    res="$(test_nightly "$cur")"
    kind="${res%% *}"; secs="${res#* }"; [ "$kind" = "UNAVAILABLE" ] && secs=""
    log "  scan nightly-$cur -> $res"
    echo "$cur,$kind,$secs" >> "$SCAN_CSV"
    cur=$(date -d "$cur + $SCAN_STEP_DAYS days" +%F)
  done
  log "Scan complete -> $SCAN_CSV"
  echo; echo "===== LANDSCAPE ====="; column -t -s, "$SCAN_CSV"; echo "====================="; echo
}

# Read the CSV and set INTRO_GOOD/INTRO_BAD (first good->bad transition) and, if a
# later good exists (a fix), FIX_BAD/FIX_GOOD (last bad -> first good after it).
analyze_scan() {
  local prev_date="" prev_kind="" date kind secs seen_bad="" last_bad=""
  INTRO_GOOD=""; INTRO_BAD=""; FIX_BAD=""; FIX_GOOD=""
  while IFS=, read -r date kind secs; do
    [ "$date" = "date" ] && continue
    case "$kind" in GOOD|BAD) ;; *) continue ;; esac
    if [ "$kind" = "BAD" ]; then
      [ -z "$INTRO_BAD" ] && [ "$prev_kind" = "GOOD" ] && { INTRO_GOOD="$prev_date"; INTRO_BAD="$date"; }
      seen_bad=1; last_bad="$date"
    elif [ "$kind" = "GOOD" ] && [ -n "$seen_bad" ] && [ -z "$FIX_GOOD" ]; then
      FIX_BAD="$last_bad"; FIX_GOOD="$date"     # transitioned back to fast => fixed
    fi
    prev_date="$date"; prev_kind="$kind"
  done < "$SCAN_CSV"
}

############################  PR BISECTION  ############################
# Modern cargo-bisect-rustc auto-continues from nightly bisection into per-PR
# commit bisection, so the first run usually already prints "Regression in <sha>".
# The fallback below covers the case where it stops at nightly granularity (older
# binary, or CI-artifact fetch skipped): we resolve the adjacent nightlies to
# commit SHAs and bisect commits directly — which doesn't depend on --by-commit
# accepting dates. Result is left in globals LAST_REG_SHA / LAST_REG_URL.
LAST_REG_SHA=""; LAST_REG_URL=""
run_bisect() {
  local mode="$1" start="$2" end="$3" outfile="$4"   # mode: error|success
  local extra=(); [ "$PRESERVE" = "1" ] && extra+=(--preserve)
  export REPRO_DIR THRESHOLD_SECS
  LAST_REG_SHA=""; LAST_REG_URL=""

  log "cargo-bisect-rustc (--regress=$mode) nightly-$start .. nightly-$end  -> $outfile"
  cargo-bisect-rustc \
    --script "$REPRO_DIR/predicate.sh" \
    --start "$start" --end "$end" \
    --regress "$mode" \
    --timeout $((THRESHOLD_SECS + 120)) \
    "${extra[@]}" \
    2>&1 | tee "$outfile"

  local sha; sha="$(extract_sha "$outfile")"

  # ---- fallback: force commit-level bisection if no commit SHA was found ----
  if [ -z "$sha" ]; then
    local bad_n good_sha bad_sha cfile
    bad_n="$(extract_regressed_nightly "$outfile")"; bad_n="${bad_n:-$end}"
    log "No commit SHA in $outfile — stopped at nightly granularity. Forcing commit-level bisect."
    log "  resolving SHAs: good bound nightly-$start, bad bound nightly-$bad_n ..."
    good_sha="$(commit_sha_of_nightly "$start")"
    bad_sha="$(commit_sha_of_nightly "$bad_n")"
    if [ -n "$good_sha" ] && [ -n "$bad_sha" ]; then
      cfile="${outfile%.log}-commits.log"
      log "cargo-bisect-rustc (--regress=$mode) commits ${good_sha:0:12} .. ${bad_sha:0:12}  -> $cfile"
      cargo-bisect-rustc \
        --script "$REPRO_DIR/predicate.sh" \
        --start "$good_sha" --end "$bad_sha" \
        --regress "$mode" \
        --timeout $((THRESHOLD_SECS + 120)) \
        "${extra[@]}" \
        2>&1 | tee "$cfile"
      sha="$(extract_sha "$cfile")"
      outfile="$cfile"
    else
      log "  could not resolve SHAs (good='$good_sha' bad='$bad_sha') — reporting nightly granularity only."
    fi
  fi

  if [ -n "$sha" ]; then
    LAST_REG_SHA="$sha"
    LAST_REG_URL="https://github.com/rust-lang/rust/commit/$sha"
    log "==> Pinpointed commit: $sha"
    log "==> $LAST_REG_URL   (bors merge — its message links the originating PR)"
  else
    log "==> Only nightly-level bounds available; inspect $outfile for the good/bad nightlies."
  fi
  log "Tail of $outfile:"; tail -n 25 "$outfile"
}

############################  MAIN  ############################
RESULT_INTRO_SHA=""; RESULT_INTRO_URL=""; RESULT_FIX_SHA=""; RESULT_FIX_URL=""
on_exit() {
  echo
  log "===== SUMMARY ====="
  [ -f "$SCAN_CSV" ] && { echo "Landscape ($SCAN_CSV):"; column -t -s, "$SCAN_CSV" 2>/dev/null; echo; }
  if [ -n "$RESULT_INTRO_SHA" ]; then
    echo "INTRODUCED BY: $RESULT_INTRO_SHA"
    echo "               $RESULT_INTRO_URL"
  else
    echo "INTRODUCED BY: (no commit pinpointed — see logs)"
  fi
  if [ -n "$RESULT_FIX_SHA" ]; then
    echo "FIXED BY:      $RESULT_FIX_SHA"
    echo "               $RESULT_FIX_URL"
  fi
  echo "Logs in: $WORK_DIR"
  log "==================="
}
trap on_exit EXIT

log "tfhe-fft codegen-regression bisect starting. Logs -> $WORK_DIR"
preflight
make_repro
sanity_gate

if [ "$SKIP_SCAN" != "1" ]; then
  landscape_scan
  analyze_scan
else
  log "SKIP_SCAN=1 — using provided INTRO_GOOD=$INTRO_GOOD INTRO_BAD=$INTRO_BAD"
  FIX_BAD=""; FIX_GOOD=""
fi

log "Boundaries: INTRO_GOOD=${INTRO_GOOD:-?} INTRO_BAD=${INTRO_BAD:-?} FIX_BAD=${FIX_BAD:-none} FIX_GOOD=${FIX_GOOD:-none}"

if [ "$SKIP_BISECT" = "1" ]; then
  log "SKIP_BISECT=1 — stopping after scan."; exit 0
fi

if [ -n "$INTRO_GOOD" ] && [ -n "$INTRO_BAD" ]; then
  run_bisect error "$INTRO_GOOD" "$INTRO_BAD" "$WORK_DIR/bisect-introduction.log"
  RESULT_INTRO_SHA="$LAST_REG_SHA"; RESULT_INTRO_URL="$LAST_REG_URL"
else
  log "No good->bad transition found in scan range — cannot bisect introduction. Widen SCAN_START/SCAN_END or set INTRO_GOOD/INTRO_BAD manually."
fi

if [ -n "${FIX_GOOD:-}" ] && [ -n "${FIX_BAD:-}" ]; then
  log "Scan shows the regression was later FIXED (nightly-$FIX_BAD bad -> nightly-$FIX_GOOD good). Bisecting the fix PR..."
  run_bisect success "$FIX_BAD" "$FIX_GOOD" "$WORK_DIR/bisect-fix.log"
  RESULT_FIX_SHA="$LAST_REG_SHA"; RESULT_FIX_URL="$LAST_REG_URL"
else
  log "No later 'good' nightly observed — regression appears STILL PRESENT through nightly-$SCAN_END (not fixed in 1.97/1.98 yet)."
fi

log "All done."
