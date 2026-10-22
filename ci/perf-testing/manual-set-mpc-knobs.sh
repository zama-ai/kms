#!/usr/bin/env bash
#=============================================================================
# manual-set-mpc-knobs.sh
#
# Change kms-server MPC tuning knobs across ALL 13 threshold parties WITHOUT a
# git commit and WITHOUT a teardown/re-up. It patches the live per-party config
# ConfigMaps and does a ROLLING restart so each kms-server re-reads them.
#
# These three are CONFIG-FILE values (rendered into the `kms-server.toml` key of
# `<release>-core-config`), NOT env vars, and kms-server reads them ONCE at
# startup (the rayon/tokio pools + preproc session count are fixed at boot). So
# a pod restart is unavoidable — but a rolling restart preserves PVCs, signing
# keys, and the Helm releases; it is not a teardown.
#
#   Knob (env)   ConfigMap line          chart value (kmsCore.thresholdMode.*)
#   RAYON        num_rayon_threads       rayonNumThreads
#   TOKIO        num_tokio_threads       tokioWorkerThreads   (kms-server, NOT the tunnel)
#   PREPROC      num_sessions_preproc    numSessionsPreproc
#
# Bench knobs (instrumentation + experimental fixes, see BENCH-DIAGNOSTICS.md) are
# environment variables of the kms-server PROCESS. An enclave does not inherit the
# pod environment, so they travel in the `[tuning.env]` table of kms-server.toml,
# which kms-server exports into its own environment at start-up (chart value
# kmsCore.tuning.env). Set/replace the whole table with:
#
#   TUNING_ENV="MPC_DKG_PHASE_LOG_EVERY=100,MPC_C2C_CONNECTIONS_PER_PEER=4"
#
# (comma-separated KEY=VALUE; an empty string TUNING_ENV="" removes the table).
#
# Why ConfigMap-patch and not `helm upgrade --set`: helm re-renders the WHOLE
# local chart, so it would also push any other uncommitted chart edits (e.g. the
# tunnel mtu/queueCount changes) and could roll the parent-side MTU out of sync
# with the enclave EIF. Patching the ConfigMaps touches ONLY these three lines
# and the [tuning.env] table.
#
# WHERE TO RUN: your laptop (kubectl + Tailscale). Needs `kubectl` and `jq`.
#
# Usage (set only the knobs you want; unset ones are left untouched):
#   NS=<namespace> RAYON=52 TOKIO=7 PREPROC=90 bash manual-set-mpc-knobs.sh
#   NS=<namespace> RAYON=52 bash manual-set-mpc-knobs.sh          # just rayon
#   NS=<namespace> RAYON=52 DRY_RUN=1 bash manual-set-mpc-knobs.sh # preview only
#   NS=<namespace> PREPROC=64 RESTART=0 bash manual-set-mpc-knobs.sh # patch, don't restart yet
#
# NOTE: the rolling restart wipes any in-flight DKG. Run this FIRST, then launch
# a fresh preproc (e.g. PREPROC_ONLY=1 manual-dkg-under-load.sh).
#=============================================================================

set -euo pipefail

NS="${NS:?set NS=<namespace>}"
NUM_PARTIES="${NUM_PARTIES:-13}"
RAYON="${RAYON:-}"
TOKIO="${TOKIO:-}"
PREPROC="${PREPROC:-}"
TUNING_SET="${TUNING_ENV+set}"   # distinguishes "unset" (leave the table alone) from "" (remove it)
TUNING_ENV="${TUNING_ENV:-}"
RESTART="${RESTART:-1}"     # 1 = rolling-restart the statefulsets after patching
DRY_RUN="${DRY_RUN:-0}"     # 1 = show the diff, don't apply

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
command -v jq      >/dev/null || { echo "jq not found"      >&2; exit 1; }

if [ -z "${RAYON}" ] && [ -z "${TOKIO}" ] && [ -z "${PREPROC}" ] && [ -z "${TUNING_SET}" ]; then
  echo "nothing to do: set at least one of RAYON=, TOKIO=, PREPROC=, TUNING_ENV=" >&2
  exit 1
fi
if [ -n "${TUNING_SET}" ] && [ -n "${TUNING_ENV}" ]; then
  IFS=',' read -r -a TUNING_PAIRS <<< "${TUNING_ENV}"
  for pair in "${TUNING_PAIRS[@]}"; do
    case "$pair" in
      (*) if ! [[ "$pair" =~ ^[A-Z][A-Z0-9_]*=[A-Za-z0-9_.:/+-]+$ ]]; then
            echo "TUNING_ENV entries must be uppercase KEY=VALUE with a simple scalar value: $pair" >&2
            exit 1
          fi ;;
    esac
  done
fi
for v in RAYON TOKIO PREPROC; do
  val="$(eval echo "\${$v}")"
  [ -z "$val" ] && continue
  case "$val" in (0|*[!0-9]*) echo "$v must be a positive integer, got '$val'" >&2; exit 1;; esac
done

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

# sed program: only rewrite the lines for the knobs that were provided. The
# lines are indented inside the TOML `|` block, so anchor on leading whitespace.
build_sed() {
  local prog=""
  [ -n "${RAYON}"   ] && prog+="s|^\([[:space:]]*num_rayon_threads[[:space:]]*=[[:space:]]*\).*|\1${RAYON}|;"
  [ -n "${TOKIO}"   ] && prog+="s|^\([[:space:]]*num_tokio_threads[[:space:]]*=[[:space:]]*\).*|\1${TOKIO}|;"
  [ -n "${PREPROC}" ] && prog+="s|^\([[:space:]]*num_sessions_preproc[[:space:]]*=[[:space:]]*\).*|\1${PREPROC}|;"
  printf '%s' "$prog"
}
SED_PROG="$(build_sed)"

# Rewrite the `[tuning.env]` table of a kms-server.toml body: drop the existing table (header up
# to the next `[...]` header or EOF) and, when TUNING_ENV is non-empty, append a fresh one. The
# TOML lives inside a YAML block scalar, so every line keeps the indentation of the first line.
rewrite_tuning_env() {
  local body="$1" indent
  indent="$(printf '%s\n' "$body" | awk 'NF {match($0,/^[[:space:]]*/); print substr($0,1,RLENGTH); exit}')"
  local stripped
  stripped="$(printf '%s\n' "$body" | awk '
    /^[[:space:]]*\[tuning\.env\][[:space:]]*$/ { skip=1; next }
    skip && /^[[:space:]]*\[/ { skip=0 }
    skip && /^[[:space:]]*#/ { next }
    !skip { print }
  ')"
  # trim trailing blank lines
  stripped="$(printf '%s\n' "$stripped" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
  if [ -z "${TUNING_ENV}" ]; then
    printf '%s\n' "$stripped"
    return
  fi
  {
    printf '%s\n' "$stripped"
    printf '\n%s[tuning.env]\n' "$indent"
    for pair in "${TUNING_PAIRS[@]}"; do
      printf '%s%s = "%s"\n' "$indent" "${pair%%=*}" "${pair#*=}"
    done
  }
}

# Find the per-party config ConfigMaps: those whose kms-server.toml carries the
# knobs (robust to naming; typically kms-core-<i>-core-config).
say "scanning ConfigMaps in ns=${NS} for kms-server.toml with the knobs ..."
CONFIGMAPS="$(kubectl get cm -n "$NS" -o json)"
mapfile -t CMS < <(printf '%s' "$CONFIGMAPS" | jq -r '.items[] | select(.data["kms-server.toml"] // "" | contains("num_rayon_threads")) | .metadata.name')
if [ "${#CMS[@]}" -ne "${NUM_PARTIES}" ]; then
  echo "expected ${NUM_PARTIES} party ConfigMaps, found ${#CMS[@]} in ns=${NS}" >&2
  exit 1
fi
STATEFULSETS="$(kubectl get sts -n "$NS" -l app=kms-core -o name)"
mapfile -t STS <<< "$STATEFULSETS"
[ "${#STS[@]}" -eq "${NUM_PARTIES}" ] && [ -n "$STATEFULSETS" ] || { echo "unexpected StatefulSet count" >&2; exit 1; }
say "found ${#CMS[@]} config ConfigMap(s): ${CMS[*]}"
say "setting: ${RAYON:+num_rayon_threads=${RAYON} }${TOKIO:+num_tokio_threads=${TOKIO} }${PREPROC:+num_sessions_preproc=${PREPROC} }${TUNING_SET:+[tuning.env]=\"${TUNING_ENV}\"}"

patched=0
for cm in "${CMS[@]}"; do
  cur="$(kubectl get cm "$cm" -n "$NS" -o json | jq -r '.data["kms-server.toml"]')"
  new="$cur"
  [ -n "${SED_PROG}" ] && new="$(printf '%s' "$new" | sed "${SED_PROG}")"
  [ -n "${TUNING_SET}" ] && new="$(rewrite_tuning_env "$new")"
  if [ "$cur" = "$new" ]; then
    say "  ${cm}: no change (already at target?)"
    continue
  fi
  if [ "${DRY_RUN}" = "1" ]; then
    say "  ${cm}: would change:"
    diff <(printf '%s\n' "$cur") <(printf '%s\n' "$new") | grep -E '^[<>]' | sed 's/^/      /' || true
    continue
  fi
  kubectl patch cm "$cm" -n "$NS" --type merge \
    -p "$(jq -n --arg v "$new" '{data:{"kms-server.toml":$v}}')" >/dev/null \
    || { say "${cm}: patch failed; no benchmark may start on this partial configuration"; exit 1; }
  say "  ${cm}: patched"; patched=$((patched+1))
  actual="$(kubectl get cm "$cm" -n "$NS" -o json | jq -r '.data["kms-server.toml"]')"
  [ "$actual" = "$new" ] || { say "${cm}: configuration readback differs"; exit 1; }
done

if [ "${DRY_RUN}" = "1" ]; then
  say "dry run complete — nothing applied. Re-run without DRY_RUN=1 to apply."
  exit 0
fi
say "patched ${patched}/${#CMS[@]} ConfigMap(s)."

if [ "${RESTART}" != "1" ]; then
  say "RESTART=0 -> ConfigMaps updated but pods NOT restarted; they keep the old"
  say "values until you: kubectl rollout restart statefulset -n ${NS} -l app=kms-core"
  exit 0
fi

say "rolling-restart of all kms-core statefulsets (wipes any in-flight DKG) ..."
kubectl rollout restart statefulset -n "$NS" -l app=kms-core
for sts in "${STS[@]}"; do
  kubectl rollout status "$sts" -n "$NS" --timeout=600s || { say "${sts}: rollout failed"; exit 1; }
done

# Confirm the value landed in one party's rendered config.
say "verify (party in ${CMS[0]}):"
kubectl get cm "${CMS[0]}" -n "$NS" -o json | jq -r '.data["kms-server.toml"]' \
  | grep -E 'num_(rayon_threads|tokio_threads|sessions_preproc)|\[tuning\.env\]|^[[:space:]]*(MPC|KMS)_' | sed 's/^/    /'
say "done. Launch a fresh preproc run now (e.g. PREPROC_ONLY=1 manual-dkg-under-load.sh)."
