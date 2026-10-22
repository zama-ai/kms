#!/usr/bin/env bash
# Run one preprocessing experiment with explicit configuration and a verified fleet.
# Defaults: 1800 seconds including a 180-second warm-up; all 13 parties are sampled.
# DURATION_SECONDS=0 selects STOP_TRACKER=BitGen / STOP_PCT=5 instead.
# REQUIRE_COMPLETION=1 ignores duration/progress stops and requires a successful driver exit.
# MAX_MINUTES is a failure watchdog. Interruptions and incomplete captures are invalid.
# Every run resets TOKIO, RAYON, PREPROC, and the complete TUNING_ENV table.
set -Eeuo pipefail
umask 077

NS="${NS:?set NS=<namespace>}"
TAG="${TAG:?set TAG=<unique run tag>}"
[[ "$NS" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || { echo "invalid namespace" >&2; exit 1; }
[[ "$TAG" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "invalid run tag" >&2; exit 1; }
RUNS_DIR="${RUNS_DIR:-$HOME/Code/ai/DkgDdecBench/runs}"
RUN_DIR="$RUNS_DIR/$TAG"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKIO="${TOKIO:-10}"
RAYON="${RAYON:-60}"
PREPROC="${PREPROC:-90}"
TUNING_ENV="${TUNING_ENV-MPC_DKG_PHASE_LOG_EVERY=100,MPC_DKG_TRACKER_LOG_PERCENTAGE=1}"
DURATION_SECONDS="${DURATION_SECONDS:-1800}"
WARMUP_SECONDS="${WARMUP_SECONDS:-180}"
STOP_TRACKER="${STOP_TRACKER:-BitGen}"
STOP_PCT="${STOP_PCT:-5}"
MAX_MINUTES="${MAX_MINUTES:-75}"
NUM_PARTIES="${NUM_PARTIES:-13}"
PARTIES="${PARTIES:-$(seq -s ' ' 1 "$NUM_PARTIES")}"
INTERVAL="${INTERVAL:-10}"
POLL_SECS="${POLL_SECS:-10}"
SETTLE_SECS="${SETTLE_SECS:-60}"
HANDSHAKE_SECONDS="${HANDSHAKE_SECONDS:-120}"
CLIENT_POD="${CLIENT_POD:-kms-core-client-0}"
CORE_CONTAINER="${CORE_CONTAINER:-}"
REFERENCE_FLEET="${REFERENCE_FLEET:-}"
REQUIRE_COMPLETION="${REQUIRE_COMPLETION:-0}"
ANALYSE="$SCRIPT_DIR/analyse_run.py"
VERIFIER="$SCRIPT_DIR/verify_bench_state.py"

say() { echo "[$(date -u +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
for tool in kubectl python3; do command -v "$tool" >/dev/null || die "$tool not found"; done
for key in TOKIO RAYON PREPROC NUM_PARTIES INTERVAL POLL_SECS MAX_MINUTES HANDSHAKE_SECONDS; do
  value="${!key}"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$key must be a positive integer"
done
for key in DURATION_SECONDS WARMUP_SECONDS SETTLE_SECS; do
  [[ "${!key}" =~ ^[0-9]+$ ]] || die "$key must be a nonnegative integer"
done
[ "$HANDSHAKE_SECONDS" -le 120 ] || die "HANDSHAKE_SECONDS must not exceed 120"
[[ "$STOP_TRACKER" = BitGen || "$STOP_TRACKER" = TripleGen ]] || die "invalid STOP_TRACKER"
[[ "$REQUIRE_COMPLETION" = 0 || "$REQUIRE_COMPLETION" = 1 ]] || die "REQUIRE_COMPLETION must be 0 or 1"
[[ "$STOP_PCT" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "invalid STOP_PCT"
[ "$DURATION_SECONDS" -eq 0 ] || [ "$DURATION_SECONDS" -gt "$WARMUP_SECONDS" ] || die "duration must exceed warm-up"
[ "${ABORT_AFTER:-1}" = 1 ] || die "ABORT_AFTER=0 is incompatible with isolated experiments"
[ "${RESTART_BEFORE:-1}" = 1 ] || die "RESTART_BEFORE=0 is incompatible with isolated experiments"
python3 - "$PARTIES" "$NUM_PARTIES" <<'PY'
import sys
parties = [int(p) for p in sys.argv[1].split()]
if sorted(parties) != list(range(1, int(sys.argv[2]) + 1)):
    raise SystemExit("PARTIES must contain every expected party exactly once")
PY
[ -f "$VERIFIER" ] && [ -f "$ANALYSE" ] || die "missing experiment tooling"
[ ! -e "$RUN_DIR" ] || die "$RUN_DIR already exists; choose another TAG"
mkdir -p "$RUNS_DIR"
LOCK_DIR="$RUNS_DIR/.namespace-$NS.lock"
mkdir "$LOCK_DIR" || die "another local experiment holds $LOCK_DIR"
mkdir -p "$RUN_DIR"/{core,raw,client,start,end}
STATUS=invalid
INVALID_REASON=""
STOPPED_BECAUSE="setup"
MUTATED=0
LAUNCHED=0
COMPLETED=0
FINISHED=0
WATCH_PID=""
CAPTURE_PID=""
TOP_PID=""
MEASUREMENT_START=""
MEASUREMENT_END=""
READY_FILE="$RUN_DIR/metrics.ready"
STOP_FILE="$RUN_DIR/metrics.stop"
STATEFULSETS=""

manifest_set() {
  python3 - "$RUN_DIR/manifest.json" "$@" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text()) if path.exists() else {}
for key, value in zip(sys.argv[2::2], sys.argv[3::2]):
    typed = {"schema_version", "num_parties", "watched_parties", "warmup_seconds",
             "duration_seconds", "measurement_start_epoch", "measurement_end_epoch", "knobs", "require_completion",
             "scrape_interval_seconds", "capture_end_epoch"}
    data[key] = json.loads(value) if key in typed else value
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
PY
}
invalidate() {
  STATUS=invalid
  INVALID_REASON="${INVALID_REASON:+$INVALID_REASON; }$*"
  say "invalid run: $*" >&2
}
client_sh() { kubectl exec -n "$NS" "$CLIENT_POD" -- sh -c "$1"; }
preexisting_driver() {
  client_sh 'for p in /proc/[0-9]*; do
    if grep -qa "kms-core-clien[t]\|driver[.]s[h]\|[-]driver[.]s[h]" "$p/cmdline" 2>/dev/null; then echo running; break; fi
  done'
}
driver_state() {
  client_sh "if [ -f /tmp/$TAG-exit-code ]; then printf 'exit '; cat /tmp/$TAG-exit-code;
    elif [ -f /tmp/$TAG-driver.pid ] && grep -q '/tmp/$TAG-driver.sh' /proc/\$(cat /tmp/$TAG-driver.pid)/cmdline 2>/dev/null; then echo running;
    else echo missing; fi"
}
kill_own_driver() {
  # RUN is inherited by this driver's descendants. Match that exact environment entry.
  client_sh "for p in /proc/[0-9]*; do
    if tr '\000' '\n' < \"\$p/environ\" 2>/dev/null | grep -Fxq 'RUN=$TAG'; then
      kill \"\${p#/proc/}\" 2>/dev/null || true
    fi
  done"
}
capture_client() {
  local destination="$1" previous="${2:-}" reference=""
  kubectl get pod -n "$NS" "$CLIENT_POD" -o json > "$destination/client-pod.json" || return
  kubectl exec -n "$NS" "$CLIENT_POD" -- cat /app/kms-core-client/config.toml > "$destination/client-config.toml" || return
  if [ -n "$REFERENCE_FLEET" ]; then reference="$(dirname "$REFERENCE_FLEET")/client-state.json"; fi
  python3 - "$destination" "$previous" "$reference" <<'PY'
import hashlib, json, sys
from pathlib import Path
directory = Path(sys.argv[1])
pod = json.loads((directory / "client-pod.json").read_text())
config = (directory / "client-config.toml").read_bytes()
if not config:
    raise SystemExit("client configuration is empty")
status = pod.get("status", {})
if pod["metadata"].get("deletionTimestamp") or not any(
    c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])
):
    raise SystemExit("client pod is not Ready")
declared = {c["name"]: c for c in pod["spec"].get("containers", []) + pod["spec"].get("initContainers", [])}
statuses = status.get("containerStatuses", []) + status.get("initContainerStatuses", [])
if not declared or set(declared) != {c["name"] for c in statuses} or any(not c.get("imageID") for c in statuses):
    raise SystemExit("client image provenance is incomplete")
containers = {}
for container in statuses:
    name = container["name"]
    containers[name] = {
        "image_id": container["imageID"], "restarts": container.get("restartCount", 0),
        "started_at": container.get("state", {}).get("running", {}).get("startedAt"),
        "runtime_spec_sha256": hashlib.sha256(json.dumps({
            key: declared[name].get(key) for key in ("args", "command", "env", "envFrom", "resources", "securityContext")
        }, sort_keys=True).encode()).hexdigest(),
    }
current = {"uid": pod["metadata"]["uid"], "node": pod["spec"]["nodeName"], "containers": containers,
           "config_sha256": hashlib.sha256(config).hexdigest()}
if sys.argv[2] and json.loads(Path(sys.argv[2]).read_text()) != current:
    raise SystemExit("client pod, image, configuration, or restart state changed during measurement")
if sys.argv[3] and Path(sys.argv[3]).exists():
    reference = json.loads(Path(sys.argv[3]).read_text())
    if any(reference[key] != current[key] for key in ("node", "config_sha256")) or reference["containers"].keys() != containers.keys():
        raise SystemExit("client placement, configuration, or container set differs from the paired reference")
    for name, value in containers.items():
        if any(reference["containers"][name][key] != value[key] for key in ("image_id", "runtime_spec_sha256")):
            raise SystemExit("client image or runtime differs from the paired reference")
(directory / "client-state.json").write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
PY
}
snapshot() {
  local destination="$1"
  kubectl get pods -n "$NS" -l app=kms-core -o json > "$destination/pods.json" || return
  kubectl get cm -n "$NS" -o json > "$destination/configmaps.json" || return
  local i pod
  for i in $(seq 1 "$NUM_PARTIES"); do
    pod="kms-core-$i-core-$i"
    if [ "$destination" = "$RUN_DIR/start" ]; then
      kubectl logs -n "$NS" "$pod" -c "$CORE_CONTAINER" --timestamps > "$destination/$pod.log" || return
    else
      cp "$RUN_DIR/start/$pod.log" "$destination/$pod.log" || return
    fi
  done
  local previous=()
  [ "$destination" != "$RUN_DIR/end" ] || previous=(--previous "$RUN_DIR/start/fleet.json")
  python3 "$VERIFIER" "$destination" --parties "$NUM_PARTIES" --tokio "$TOKIO" --rayon "$RAYON" \
    --preproc "$PREPROC" --tuning "$TUNING_ENV" "${previous[@]}" > "$destination/fleet.json" || return
  local client_previous=""
  [ "$destination" != "$RUN_DIR/end" ] || client_previous="$RUN_DIR/start/client-state.json"
  capture_client "$destination" "$client_previous"
}
wait_pid() {
  local pid="$1" limit="$2" started
  started="$(date +%s)"
  while kill -0 "$pid" 2>/dev/null; do
    [ "$(( $(date +%s) - started ))" -lt "$limit" ] || return 124
    sleep 1
  done
  wait "$pid"
}
stop_collector() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  if ! wait_pid "$pid" 10; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
cleanup_rollout() {
  local sts
  kubectl rollout restart statefulset -n "$NS" -l app=kms-core || return
  for sts in $STATEFULSETS; do
    kubectl rollout status "$sts" -n "$NS" --timeout=600s || return
  done
}
finish() {
  local exit_code="$1"
  [ "$FINISHED" = 0 ] || return
  FINISHED=1
  trap - ERR EXIT INT TERM
  set +e
  if [ "$exit_code" -ne 0 ] && [ -z "$INVALID_REASON" ]; then invalidate "command failed (exit $exit_code)"; fi
  if [ "$LAUNCHED" = 1 ]; then
    [ -n "$MEASUREMENT_END" ] || MEASUREMENT_END="$(python3 -c 'import time; print(time.time())')"
    manifest_set measurement_end_epoch "$MEASUREMENT_END"
  fi
  if [ -n "$WATCH_PID" ]; then
    touch "$STOP_FILE"
    if ! wait_pid "$WATCH_PID" "$HANDSHAKE_SECONDS"; then
      invalidate "metrics collector failed or did not complete its final round"
      stop_collector "$WATCH_PID"
    fi
  fi
  if [ "$LAUNCHED" = 1 ]; then
    manifest_set capture_end_epoch "$(python3 -c 'import time; print(time.time())')"
  fi
  stop_collector "$CAPTURE_PID"
  stop_collector "$TOP_PID"
  if [ "$LAUNCHED" = 1 ]; then
    snapshot "$RUN_DIR/end" > "$RUN_DIR/end/verification.log" 2>&1 || invalidate "fleet changed or final fleet verification failed"
    kill_own_driver > "$RUN_DIR/client/stop.log" 2>&1 || invalidate "could not stop this run's driver"
    for suffix in driver.log preproc-only.log exit-code; do
      if ! kubectl cp "$NS/$CLIENT_POD:/tmp/$TAG-$suffix" "$RUN_DIR/client/$TAG-$suffix" >/dev/null 2>&1; then
        if [ "$COMPLETED" = 1 ] && [ "$suffix" != driver.log ]; then invalidate "missing completion artifact: $suffix"; fi
      fi
    done
    if [ "$COMPLETED" = 1 ]; then
      [ -s "$RUN_DIR/client/$TAG-preproc-only.log" ] || invalidate "completion log is empty or missing"
      [ "$(tr -d '[:space:]' < "$RUN_DIR/client/$TAG-exit-code" 2>/dev/null)" = 0 ] || invalidate "completion artifact does not confirm exit code 0"
    fi
  fi
  # All measurements and provenance checks precede this restart.
  if [ "$MUTATED" = 1 ]; then
    cleanup_rollout > "$RUN_DIR/cleanup-rollout.log" 2>&1 || invalidate "cleanup rollout failed; preprocessing may still be active"
  fi
  [ "$STATUS" = valid ] || [ -n "$INVALID_REASON" ] || invalidate "experiment did not reach a valid stop condition"
  manifest_set status "$STATUS" invalid_reason "$INVALID_REASON" stopped_because "$STOPPED_BECAUSE" \
    end "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! python3 "$ANALYSE" summarize "$RUN_DIR" --stop-pct "$STOP_PCT"; then
    invalidate "analysis rejected the capture"
    manifest_set status "$STATUS" invalid_reason "$INVALID_REASON"
    python3 "$ANALYSE" summarize "$RUN_DIR" --stop-pct "$STOP_PCT" || true
  fi
  if [ "$STATUS" = valid ] && ! python3 - "$RUN_DIR/summary.json" <<'PY'
import json, sys
try:
    summary = json.load(open(sys.argv[1]))
    if summary["row"]["status"] != "valid":
        raise ValueError("analysis did not validate this capture")
except (OSError, ValueError, KeyError) as error:
    raise SystemExit(str(error))
PY
  then
    invalidate "analysis marked the capture invalid or exploratory"
    manifest_set status "$STATUS" invalid_reason "$INVALID_REASON"
    python3 "$ANALYSE" summarize "$RUN_DIR" --stop-pct "$STOP_PCT" || true
  fi
  rmdir "$LOCK_DIR" || true
  say "$TAG: $STATUS ($STOPPED_BECAUSE); files: $RUN_DIR"
  [ "$STATUS" = valid ] && exit 0
  [ "$exit_code" -ne 0 ] && exit "$exit_code"
  exit 1
}
trap 'finish $?' EXIT
trap 'invalidate "interrupted"; exit 130' INT TERM
trap 'invalidate "command failed at line $LINENO"; exit 1' ERR

WATCHED_JSON="$(python3 -c 'import json,sys; print(json.dumps([int(p) for p in sys.argv[1].split()]))' "$PARTIES")"
KNOBS_JSON="$(python3 -c 'import json,sys; print(json.dumps(dict(zip(["TOKIO","RAYON","PREPROC","TUNING_ENV"],sys.argv[1:]))))' "$TOKIO" "$RAYON" "$PREPROC" "$TUNING_ENV")"
manifest_set schema_version 2 tag "$TAG" namespace "$NS" start "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  status invalid invalid_reason "setup incomplete" num_parties "$NUM_PARTIES" watched_parties "$WATCHED_JSON" \
  warmup_seconds "$WARMUP_SECONDS" duration_seconds "$DURATION_SECONDS" knobs "$KNOBS_JSON" \
  require_completion "$REQUIRE_COMPLETION" scrape_interval_seconds "$INTERVAL" \
  git_head "$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
kubectl get ns "$NS" >/dev/null
kubectl get pod -n "$NS" "$CLIENT_POD" >/dev/null
active_driver="$(preexisting_driver)"
[ -z "$active_driver" ] || die "a driver or kms-core-client already runs; no cluster changes were made"
client_sh "test ! -e /tmp/$TAG-driver.pid && test ! -e /tmp/$TAG-exit-code" || die "remote TAG files already exist"
kubectl get pods -n "$NS" -l app=kms-core -o json > "$RUN_DIR/before-pods.json"
STATEFULSETS="$(kubectl get sts -n "$NS" -l app=kms-core -o name)"
[ "$(printf '%s\n' "$STATEFULSETS" | awk 'NF {n++} END {print n+0}')" -eq "$NUM_PARTIES" ] || die "unexpected StatefulSet count"
if [ -z "$CORE_CONTAINER" ]; then
  init_containers="$(kubectl get pod -n "$NS" kms-core-1-core-1 -o jsonpath='{.spec.initContainers[*].name}')"
  case "$init_containers" in (*kms-core-enclave-logger*) CORE_CONTAINER=kms-core-enclave-logger;; (*) CORE_CONTAINER=kms-core;; esac
fi
manifest_set core_container "$CORE_CONTAINER"
MUTATED=1
say "resetting all party knobs and restarting the fleet"
NS="$NS" NUM_PARTIES="$NUM_PARTIES" TOKIO="$TOKIO" RAYON="$RAYON" PREPROC="$PREPROC" TUNING_ENV="$TUNING_ENV" RESTART=1 \
  bash "$SCRIPT_DIR/manual-set-mpc-knobs.sh" > "$RUN_DIR/set-knobs.log" 2>&1
sleep "$SETTLE_SECS"
snapshot "$RUN_DIR/start" > "$RUN_DIR/start/verification.log" 2>&1
python3 - "$RUN_DIR/before-pods.json" "$RUN_DIR/start/fleet.json" "$REFERENCE_FLEET" "$SCRIPT_DIR" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[4])
from verify_bench_state import check_reference
before = {p["metadata"]["name"]: p["metadata"]["uid"] for p in json.load(open(sys.argv[1]))["items"]}
current = json.load(open(sys.argv[2]))
if before.keys() != current.keys() or any(before[name] == entry["uid"] for name, entry in current.items()):
    raise SystemExit("every expected party must have a new pod UID after setup")
if sys.argv[3]:
    reference = json.load(open(sys.argv[3]))
    check_reference(reference, current)
PY
NS="$NS" OUT="$RUN_DIR/cluster-facts.txt" bash "$SCRIPT_DIR/manual-cluster-facts.sh" > "$RUN_DIR/cluster-facts.log" 2>&1
NAMESPACE="$NS" PARTIES="$PARTIES" INTERVAL="$INTERVAL" LOG_FILE="$RUN_DIR/metrics-watch.log" RAW_DIR="$RUN_DIR/raw" \
  READY_FILE="$READY_FILE" STOP_FILE="$STOP_FILE" bash "$SCRIPT_DIR/manual-metrics-watch.sh" \
  > "$RUN_DIR/metrics-watch.out" 2> "$RUN_DIR/metrics-watch.err" &
WATCH_PID=$!
NAMESPACE="$NS" NUM_PARTIES="$NUM_PARTIES" RUN="$RUN_DIR/core" CONTAINER="$CORE_CONTAINER" \
  bash "$SCRIPT_DIR/manual-capture-core-logs.sh" > "$RUN_DIR/capture.out" 2>&1 &
CAPTURE_PID=$!
(
  child=""
  trap '[ -z "$child" ] || kill "$child" 2>/dev/null; exit 0' TERM INT
  while :; do
    printf '## %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    kubectl top pod -n "$NS" kms-core-1-core-1 --containers --no-headers || true
    sleep 30 & child=$!
    wait "$child" || true
  done
) > "$RUN_DIR/top-party1.log" 2>&1 &
TOP_PID=$!
wait_started="$(date +%s)"
until [ -f "$READY_FILE" ]; do
  kill -0 "$WATCH_PID" 2>/dev/null || die "metrics collector exited before initial fleet sample"
  [ "$(( $(date +%s) - wait_started ))" -lt "$HANDSHAKE_SECONDS" ] || die "initial metrics handshake timed out"
  sleep 1
done
active_driver="$(preexisting_driver)"
[ -z "$active_driver" ] || die "another driver appeared before launch"
kubectl cp "$SCRIPT_DIR/manual-dkg-under-load.sh" "$NS/$CLIENT_POD:/tmp/$TAG-driver.sh"
MEASUREMENT_START="$(python3 -c 'import time; print(time.time())')"
manifest_set measurement_start_epoch "$MEASUREMENT_START" launched "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LAUNCHED=1
DRIVER_MAX_ITER=$(( (MAX_MINUTES + 10) * 6 ))
client_sh "cd /tmp; PREPROC_ONLY=1 RUN=$TAG LOG_DIR=/tmp CFG=/app/kms-core-client/config.toml DKG_POLL_INTERVAL_MS=10000 MAX_ITER=$DRIVER_MAX_ITER nohup bash /tmp/$TAG-driver.sh > /tmp/$TAG-driver.log 2>&1 < /dev/null & echo \$! > /tmp/$TAG-driver.pid"
say "measuring all $NUM_PARTIES parties; duration=$DURATION_SECONDS seconds, warm-up=$WARMUP_SECONDS seconds"
while :; do
  sleep "$POLL_SECS"
  kill -0 "$WATCH_PID" 2>/dev/null || die "metrics collector exited during measurement"
  kill -0 "$CAPTURE_PID" 2>/dev/null || die "core log collector exited during measurement"
  elapsed="$(python3 -c 'import sys,time; print(int(time.time() - float(sys.argv[1])))' "$MEASUREMENT_START")"
  state="$(driver_state)"
  case "$state" in
    ("exit 0")
      if [ "$REQUIRE_COMPLETION" = 0 ] && [ "$DURATION_SECONDS" -gt 0 ] && [ "$elapsed" -lt "$DURATION_SECONDS" ]; then
        die "driver completed before the requested measurement interval"
      fi
      if [ "$REQUIRE_COMPLETION" = 0 ] && [ "$DURATION_SECONDS" -gt 0 ]; then
        MEASUREMENT_END="$(python3 -c 'import sys; print(float(sys.argv[1]) + int(sys.argv[2]))' "$MEASUREMENT_START" "$DURATION_SECONDS")"
      fi
      COMPLETED=1; STOPPED_BECAUSE="driver completed successfully"; STATUS=valid; break;;
    (running) ;;
    (*) die "driver stopped without a successful exit marker: $state";;
  esac
  [ "$elapsed" -lt "$((MAX_MINUTES * 60))" ] || die "MAX_MINUTES watchdog elapsed"
  if [ "$REQUIRE_COMPLETION" = 0 ] && [ "$DURATION_SECONDS" -gt 0 ] && [ "$elapsed" -ge "$DURATION_SECONDS" ]; then
    MEASUREMENT_END="$(python3 -c 'import sys; print(float(sys.argv[1]) + int(sys.argv[2]))' "$MEASUREMENT_START" "$DURATION_SECONDS")"
    STOPPED_BECAUSE="fixed duration reached"; STATUS=valid; break
  fi
  if [ "$REQUIRE_COMPLETION" = 0 ] && [ "$DURATION_SECONDS" -eq 0 ]; then
    progress="$(kubectl logs -n "$NS" kms-core-1-core-1 -c "$CORE_CONTAINER" --tail=6000 | python3 "$ANALYSE" progress - --tracker "$STOP_TRACKER")"
    say "t+${elapsed}s $STOP_TRACKER $progress"
    if awk -v value="${progress%% *}" -v target="$STOP_PCT" 'BEGIN {exit !(value >= target)}'; then
      STOPPED_BECAUSE="$STOP_TRACKER reached $STOP_PCT percent"; STATUS=valid; break
    fi
  fi
done
exit 0
