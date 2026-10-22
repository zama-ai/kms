"""Exercise experiment lifecycle failures with local Kubernetes and collector fakes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]


KUBECTL = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["MOCK_ROOT"])
scenario = os.environ.get("SCENARIO", "success")
args = sys.argv[1:]
command = " ".join(args)
def event(value):
    with (root / "events").open("a") as handle:
        handle.write(value + "\n")
stage_file = root / "stage"
stage = int(stage_file.read_text()) if stage_file.exists() else 0
if args[:2] == ["rollout", "restart"]:
    stage += 1
    stage_file.write_text(str(stage))
    event(f"restart-{stage}")
    sys.exit(1 if scenario == "cleanup_failure" and stage == 2 else 0)
if args[:2] == ["rollout", "status"]:
    event("rollout-wait")
    sys.exit(1 if scenario == "rollout_failure" and stage == 1 else 0)
if args[0] == "get" and args[1] == "sts":
    print("statefulset/kms-core-1-core-1\nstatefulset/kms-core-2-core-2")
elif args[0] == "get" and args[1] == "pods":
    event("pods-end" if (root / "launched").exists() else "pods-start")
    items = []
    for i in (1, 2):
        uid_stage = 0 if scenario == "stale_uid" else stage
        changed = scenario == "changed_fleet" and (root / "launched").exists()
        ready = not (scenario == "not_ready" and stage == 1 and i == 2)
        items.append({"metadata": {"name": f"kms-core-{i}-core-{i}", "uid": f"uid-{i}-{uid_stage}"},
          "spec": {"nodeName": f"node-{i}", "containers": [{"name": "kms-core"}], "volumes": [{"configMap": {"name": f"config-{i}"}}]},
          "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "kms-core", "imageID": "sha256:test",
              "restartCount": 1 if changed else 0, "state": {"running": {"startedAt": "2026-01-01"}}}]}})
    print(json.dumps({"items": items}))
elif args[0] == "get" and args[1] == "cm":
    body = "num_tokio_threads = 10\nnum_rayon_threads = 60\nnum_sessions_preproc = 90\n"
    print(json.dumps({"items": [{"metadata": {"name": f"config-{i}"}, "data": {"kms-server.toml": body}} for i in (1, 2)]}))
elif args[0] == "logs":
    tokio = 24 if scenario == "wrong_runtime" and "kms-core-2-core-2" in args else 10
    print(f"benchmark runtime: tokio={tokio} rayon=60 preproc=90")
    print("tuning: exporting MPC_DKG_PHASE_LOG_EVERY=100 into the process environment")
    print("tuning: exporting MPC_DKG_TRACKER_LOG_PERCENTAGE=1 into the process environment")
elif args[0] == "exec":
    if "kms-health-check bandwidth-bench" in command:
        event("bandwidth-launch")
        sys.exit(1 if scenario == "bandwidth_tool_failure" else 0)
    remote = args[-1]
    if "grep -Fxq" in remote:
        event("kill-own-driver")
    elif "nohup bash" in remote:
        event("launch")
        (root / "launched").touch()
    elif "printf 'exit '" in remote:
        if scenario == "delayed_success":
            counter = root / "driver-polls"
            polls = int(counter.read_text()) + 1 if counter.exists() else 1
            counter.write_text(str(polls))
            print("exit 0" if polls == 2 else "running")
        else:
            print({"driver_failure": "exit 9", "driver_missing": "missing", "driver_success": "exit 0"}.get(scenario, "running"))
    elif "for p in /proc/" in remote:
        event("preflight")
        if scenario == "preexisting":
            print("running")
elif args[0] == "cp":
    event("copy")
elif args[0] == "top":
    print("kms-core 1m 1Mi")
'''

WATCHER = r'''#!/usr/bin/env python3
import os, time
from pathlib import Path
root = Path(os.environ["MOCK_ROOT"])
scenario = os.environ.get("SCENARIO", "success")
def event(value):
    with (root / "events").open("a") as handle:
        handle.write(value + "\n")
if scenario == "initial_scrape_failure":
    raise SystemExit(1)
Path(os.environ["READY_FILE"]).touch()
event("watcher-ready")
while not Path(os.environ["STOP_FILE"]).exists():
    time.sleep(0.01)
event("watcher-stopped")
raise SystemExit(1 if scenario == "final_scrape_failure" else 0)
'''

CAPTURE = r'''#!/usr/bin/env python3
import os, signal, time
from pathlib import Path
def stop(*_):
    with (Path(os.environ["MOCK_ROOT"]) / "events").open("a") as handle:
        handle.write("capture-stopped\n")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
while True:
    time.sleep(0.01)
'''


class ExperimentLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("manual-run-experiment.sh", "manual-bandwidth-bench.sh", "verify_bench_state.py"):
            shutil.copy(SCRIPTS / name, self.scripts / name)
        self.write(self.bin / "kubectl", KUBECTL)
        self.write(self.scripts / "watcher.py", WATCHER)
        self.write(self.scripts / "capture.py", CAPTURE)
        self.write(self.scripts / "manual-metrics-watch.sh", '#!/bin/bash\nexec python3 "$(dirname "$0")/watcher.py"\n')
        self.write(self.scripts / "manual-capture-core-logs.sh", '#!/bin/bash\nexec python3 "$(dirname "$0")/capture.py"\n')
        self.write(self.scripts / "manual-cluster-facts.sh", '#!/bin/bash\nprintf "facts\\n" > "$OUT"\n')
        self.write(self.scripts / "manual-dkg-under-load.sh", '#!/bin/bash\nexit 0\n')
        self.write(self.scripts / "manual-set-mpc-knobs.sh", textwrap.dedent('''\
            #!/bin/bash
            set -eu
            printf '%s|%s|%s|%s\n' "$TOKIO" "$RAYON" "$PREPROC" "$TUNING_ENV" > "$MOCK_ROOT/knobs"
            [ "$SCENARIO" != patch_failure ] || exit 9
            kubectl rollout restart statefulset -n "$NS" -l app=kms-core
            kubectl rollout status statefulset/kms-core-1-core-1 -n "$NS" --timeout=600s
            kubectl rollout status statefulset/kms-core-2-core-2 -n "$NS" --timeout=600s
            '''))
        self.write(self.scripts / "analyse_run.py", textwrap.dedent('''\
            import json, os, sys
            from pathlib import Path
            if sys.argv[1] == "progress":
                print("5 1")
            with (Path(os.environ["MOCK_ROOT"]) / "events").open("a") as handle:
                handle.write("analysis-" + sys.argv[1] + "\\n")
            if sys.argv[1] == "bw" and os.environ["SCENARIO"] == "bandwidth_partial":
                raise SystemExit(1)
            if sys.argv[1] == "summarize":
                run = Path(sys.argv[2])
                manifest = json.loads((run / "manifest.json").read_text())
                status = "exploratory" if os.environ["SCENARIO"] == "exploratory_analysis" else manifest["status"]
                (run / "summary.json").write_text(json.dumps({"row": {"status": status}}))
            '''))

    @staticmethod
    def write(path, text):
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, scenario="success", bandwidth=False, **overrides):
        env = os.environ.copy()
        for key in ("TUNING_ENV", "TOKIO", "RAYON", "PREPROC", "PARTIES", "REFERENCE_FLEET", "ABORT_AFTER", "RESTART_BEFORE", "RESTART_FIRST", "REQUIRE_COMPLETION"):
            env.pop(key, None)
        env.update({"PATH": str(self.bin) + os.pathsep + env["PATH"], "MOCK_ROOT": str(self.root),
                    "SCENARIO": scenario, "NS": "test-ns", "TAG": "test-run", "RUNS_DIR": str(self.root / "runs"),
                    "NUM_PARTIES": "2", "CORE_CONTAINER": "kms-core", "DURATION_SECONDS": "0",
                    "WARMUP_SECONDS": "0", "POLL_SECS": "1", "SETTLE_SECS": "0", "HANDSHAKE_SECONDS": "2",
                    "PAUSE": "0", "SHAPES": "1:100:1 2:100:1"})
        env.update(overrides)
        name = "manual-bandwidth-bench.sh" if bandwidth else "manual-run-experiment.sh"
        # Explicit Python invocation also works when the temporary filesystem is mounted noexec.
        command = 'kubectl() { python3 "$MOCK_ROOT/bin/kubectl" "$@"; }; export -f kubectl; exec bash "$1"'
        return subprocess.run(["bash", "-c", command, "mock-run", str(self.scripts / name)],
                              env=env, capture_output=True, text=True, timeout=20)

    def events(self):
        path = self.root / "events"
        return path.read_text().splitlines() if path.exists() else []

    def manifest(self):
        return json.loads((self.root / "runs/test-run/manifest.json").read_text())

    def test_valid_run_resets_defaults_and_freezes_collectors_before_cleanup(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.manifest()["status"], "valid")
        self.assertEqual(self.manifest()["watched_parties"], [1, 2])
        self.assertTrue((self.root / "knobs").read_text().startswith("10|60|90|MPC_DKG_PHASE_LOG_EVERY=100,"))
        events = self.events()
        self.assertLess(events.index("watcher-ready"), events.index("launch"))
        self.assertLess(events.index("watcher-stopped"), events.index("restart-2"))
        self.assertLess(events.index("capture-stopped"), events.index("restart-2"))
        self.assertLess(events.index("pods-end"), events.index("restart-2"))

    def test_preexisting_client_prevents_restart_and_kill(self):
        result = self.run_script("preexisting")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest()["status"], "invalid")
        self.assertNotIn("restart-1", self.events())
        self.assertNotIn("kill-own-driver", self.events())

    def test_completion_validation_waits_for_success_marker_past_progress_stop(self):
        result = self.run_script("delayed_success", REQUIRE_COMPLETION="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.manifest()["status"], "valid")
        self.assertEqual(self.manifest()["stopped_because"], "driver completed successfully")
        self.assertEqual((self.root / "driver-polls").read_text(), "2")

    def test_premature_completion_does_not_validate_a_fixed_window(self):
        result = self.run_script("driver_success", DURATION_SECONDS="10")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest()["status"], "invalid")

    def test_startup_failures_never_launch_workload(self):
        for scenario in ("wrong_runtime", "not_ready", "stale_uid", "patch_failure", "rollout_failure", "initial_scrape_failure"):
            with self.subTest(scenario=scenario):
                result = self.run_script(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("launch", self.events())
                self.assertEqual(self.manifest()["status"], "invalid")
                shutil.rmtree(self.root / "runs")
                for name in ("events", "stage", "knobs"):
                    (self.root / name).unlink(missing_ok=True)

    def test_driver_failure_or_missing_marker_is_invalid(self):
        for scenario in ("driver_failure", "driver_missing"):
            with self.subTest(scenario=scenario):
                result = self.run_script(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.manifest()["status"], "invalid")
                shutil.rmtree(self.root / "runs")
                for name in ("events", "stage", "knobs", "launched"):
                    (self.root / name).unlink(missing_ok=True)

    def test_final_failures_invalidate_successful_stop(self):
        for scenario in ("final_scrape_failure", "changed_fleet", "cleanup_failure", "exploratory_analysis"):
            with self.subTest(scenario=scenario):
                result = self.run_script(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.manifest()["status"], "invalid")
                self.assertIn("restart-2", self.events())
                shutil.rmtree(self.root / "runs")
                for name in ("events", "stage", "knobs", "launched"):
                    (self.root / name).unlink(missing_ok=True)

    def test_bandwidth_failure_prevents_next_shape_and_waits_cleanup(self):
        for scenario in ("bandwidth_tool_failure", "bandwidth_partial"):
            with self.subTest(scenario=scenario):
                result = self.run_script(scenario, bandwidth=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.events().count("bandwidth-launch"), 1)
                self.assertIn("restart-2", self.events())
                shutil.rmtree(self.root / "runs")
                for name in ("events", "stage"):
                    (self.root / name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
