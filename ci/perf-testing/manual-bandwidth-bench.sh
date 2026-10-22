#!/usr/bin/env bash
# Measure acknowledged gRPC goodput on an idle, restarted all-to-all fleet.
# Each session sends to every peer. With one connection per peer, more sessions
# add HTTP/2 streams rather than TCP connections. RPC latency is not network RTT.
# A shape is valid only when all parties complete without errors or timeouts.
set -Eeuo pipefail
umask 077
NS="${NS:?set NS=<namespace>}"
[[ "$NS" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || { echo "invalid namespace" >&2; exit 1; }
RUNS_DIR="${RUNS_DIR:-$HOME/Code/ai/DkgDdecBench/runs}"
OUT_DIR="${OUT_DIR:-$RUNS_DIR/bw-$(date -u +%Y%m%d-%H%M%S)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_POD="${CLIENT_POD:-kms-core-client-0}"
NUM_PARTIES="${NUM_PARTIES:-13}"
CONTEXT_ID="${CONTEXT_ID:-0700000000000000000000000000000000000000000000000000000000000001}"
SHAPES="${SHAPES:-1:1000000:10 12:1000000:20 85:8320000:30}"
PAUSE="${PAUSE:-20}"
SETTLE_SECS="${SETTLE_SECS:-60}"
CORE_CONTAINER="${CORE_CONTAINER:-}"
PORT="${PORT:-50100}"
say() { echo "[$(date -u +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
command -v kubectl >/dev/null || die "kubectl not found"
command -v python3 >/dev/null || die "python3 not found"
[ "${RESTART_FIRST:-1}" = 1 ] || die "RESTART_FIRST=0 cannot establish an idle fleet"
[[ "$NUM_PARTIES" =~ ^[1-9][0-9]*$ ]] || die "invalid NUM_PARTIES"
[[ "$PAUSE" =~ ^[0-9]+$ && "$SETTLE_SECS" =~ ^[0-9]+$ ]] || die "invalid pause/settle interval"
[ -n "$SHAPES" ] || die "no benchmark shapes"
for shape in $SHAPES; do
  [[ "$shape" =~ ^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$ ]] || die "invalid sessions:payload:seconds shape: $shape"
done
[ ! -e "$OUT_DIR" ] || die "$OUT_DIR already exists"
mkdir -p "$RUNS_DIR"
LOCK_DIR="$RUNS_DIR/.namespace-$NS.lock"
mkdir "$LOCK_DIR" || die "another local experiment holds $LOCK_DIR"
mkdir -p "$OUT_DIR"
BENCH_ACTIVE=0
CURRENT_DIRECTORY=""
STATEFULSETS=""
cleanup_rollout() {
  local sts
  kubectl rollout restart statefulset -n "$NS" -l app=kms-core || return
  for sts in $STATEFULSETS; do kubectl rollout status "$sts" -n "$NS" --timeout=600s || return; done
}
finish() {
  local rc="$?"
  trap - EXIT INT TERM
  set +e
  if [ "$BENCH_ACTIVE" = 1 ]; then
    if ! cleanup_rollout > "$OUT_DIR/cleanup-rollout.log" 2>&1; then
      echo "ERROR: cleanup rollout failed; benchmark work may remain active" >&2
      rc=1
    fi
  fi
  if [ "$rc" -ne 0 ] && [ -n "$CURRENT_DIRECTORY" ]; then
    python3 - "$CURRENT_DIRECTORY/summary.json" "$rc" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    summary = json.loads(path.read_text())
except (OSError, ValueError):
    summary = {}
summary["status"] = "invalid"
summary["invalid_reason"] = "bandwidth lifecycle or collection failed (exit " + sys.argv[2] + ")"
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
PY
  fi
  rmdir "$LOCK_DIR" || true
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT TERM
idle_client() {
  local active
  active="$(kubectl exec -n "$NS" "$CLIENT_POD" -- sh -c 'for p in /proc/[0-9]*; do
    if grep -qa "kms-core-clien[t]\|driver[.]s[h]\|[-]driver[.]s[h]\|kms-health-chec[k].*bandwidth-bench" "$p/cmdline" 2>/dev/null; then echo active; break; fi
  done')" || return
  [ -z "$active" ] || { echo "client work is already active; no benchmark may start" >&2; return 1; }
}
capture_pods() {
  local directory="$1" previous="${2:-}"
  mkdir -p "$directory"
  kubectl get pods -n "$NS" -l app=kms-core -o json > "$directory/pods.json" || return
  python3 - "$directory/pods.json" "$NUM_PARTIES" "$previous" > "$directory/fleet.json" <<'PY'
import json, sys
pods = json.load(open(sys.argv[1]))["items"]
expected = {f"kms-core-{i}-core-{i}" for i in range(1, int(sys.argv[2]) + 1)}
if {p["metadata"]["name"] for p in pods} != expected:
    raise SystemExit("unexpected party pod set")
fleet = {}
for pod in pods:
    name = pod["metadata"]["name"]
    status = pod.get("status", {})
    if pod["metadata"].get("deletionTimestamp") or not any(
        c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])
    ):
        raise SystemExit(f"{name} is not Ready")
    containers = status.get("containerStatuses", []) + status.get("initContainerStatuses", [])
    images = {c["name"]: [c.get("imageID"), c.get("restartCount", 0), c.get("state")] for c in containers}
    if "kms-core" not in images or any(not data[0] for data in images.values()):
        raise SystemExit(f"{name} has incomplete image provenance")
    fleet[name] = {"uid": pod["metadata"]["uid"], "node": pod["spec"]["nodeName"], "containers": images}
if len({json.dumps({k: v[0] for k, v in p["containers"].items()}, sort_keys=True) for p in fleet.values()}) != 1:
    raise SystemExit("party image identities differ")
if sys.argv[3] and json.load(open(sys.argv[3])) != fleet:
    raise SystemExit("party fleet changed during the bandwidth shape")
json.dump(fleet, sys.stdout, sort_keys=True, indent=2)
PY
}
idle_client
STATEFULSETS="$(kubectl get sts -n "$NS" -l app=kms-core -o name)"
[ "$(printf '%s\n' "$STATEFULSETS" | awk 'NF {n++} END {print n+0}')" -eq "$NUM_PARTIES" ] || die "unexpected StatefulSet count"
kubectl get pods -n "$NS" -l app=kms-core -o json > "$OUT_DIR/before-pods.json"
say "restarting every party to remove prior preprocessing"
cleanup_rollout > "$OUT_DIR/setup-rollout.log" 2>&1
sleep "$SETTLE_SECS"
capture_pods "$OUT_DIR/start"
python3 - "$OUT_DIR/before-pods.json" "$OUT_DIR/start/fleet.json" <<'PY'
import json, sys
before = {p["metadata"]["name"]: p["metadata"]["uid"] for p in json.load(open(sys.argv[1]))["items"]}
after = json.load(open(sys.argv[2]))
if before.keys() != after.keys() or any(before[name] == party["uid"] for name, party in after.items()):
    raise SystemExit("every party must restart before the benchmark")
PY
if [ -z "$CORE_CONTAINER" ]; then
  init_containers="$(kubectl get pod -n "$NS" kms-core-1-core-1 -o jsonpath='{.spec.initContainers[*].name}')"
  case "$init_containers" in (*kms-core-enclave-logger*) CORE_CONTAINER=kms-core-enclave-logger;; (*) CORE_CONTAINER=kms-core;; esac
fi
NS="$NS" OUT="$OUT_DIR/cluster-facts.txt" bash "$SCRIPT_DIR/manual-cluster-facts.sh" > "$OUT_DIR/cluster-facts.log" 2>&1
endpoints=()
for i in $(seq 1 "$NUM_PARTIES"); do endpoints+=(-e "kms-core-$i-core-$i:$PORT"); done
for shape in $SHAPES; do
  idle_client
  IFS=: read -r n p d <<< "$shape"
  directory="$OUT_DIR/n$n-p$p-d$d"
  [ ! -e "$directory" ] || die "duplicate benchmark shape: $shape"
  mkdir -p "$directory"
  CURRENT_DIRECTORY="$directory"
  capture_pods "$directory/start" "$OUT_DIR/start/fleet.json"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  say "$n sessions per party, $p-byte requests, $d seconds; every session contacts every peer"
  BENCH_ACTIVE=1
  tool_status=0
  kubectl exec -n "$NS" "$CLIENT_POD" -- env "HEALTH_CHECK__REQUEST_TIMEOUT_SECS=$((d + 300))" \
    kms-health-check bandwidth-bench -c "$CONTEXT_ID" -d "$d" -n "$n" -p "$p" "${endpoints[@]}" \
    > "$directory/tool.log" 2>&1 || tool_status=$?
  tail -n 25 "$directory/tool.log"
  logs_status=0
  for i in $(seq 1 "$NUM_PARTIES"); do
    kubectl logs -n "$NS" "kms-core-$i-core-$i" -c "$CORE_CONTAINER" --since-time="$since" --timestamps \
      > "$directory/core-$i.bench.log" 2> "$directory/core-$i.error.log" || logs_status=1
  done
  analysis_status=0
  python3 "$SCRIPT_DIR/analyse_run.py" bw "$directory"/core-*.bench.log --expected-parties "$NUM_PARTIES" \
    --json "$directory/summary.json" > "$directory/summary.txt" 2>&1 || analysis_status=$?
  cat "$directory/summary.txt"
  capture_pods "$directory/end" "$directory/start/fleet.json"
  [ "$tool_status" -eq 0 ] && [ "$logs_status" -eq 0 ] && [ "$analysis_status" -eq 0 ] \
    || die "incomplete/erroring bandwidth shape; stopping before the next shape"
  BENCH_ACTIVE=0
  CURRENT_DIRECTORY=""
  sleep "$PAUSE"
done
say "valid all-to-all gRPC samples: $OUT_DIR"
