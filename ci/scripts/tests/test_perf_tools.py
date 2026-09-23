"""Regression tests for runner orchestration and performance artifacts."""

import contextlib
import io
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_network_diagnostics as network
import perf_common as common
import perf_runner as runner
import sample_core_cpu as cpu
import sample_core_metrics as metrics
import sample_perf_diagnostics as diagnostics
import sample_pod_placement as placement


def result(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class TemporaryWorkingDirectory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, previous)
        self.env = patch.dict(
            os.environ,
            {
                "GITHUB_ENV": str(Path("github-env").resolve()),
                "GITHUB_STEP_SUMMARY": str(Path("summary").resolve()),
                "NAMESPACE": "kms-ci",
                "DEPLOYMENT_TYPE": "threshold",
                "TLS": "false",
                "CLIENT_LOGS": "false",
                "FHE_PARAMS": "Test",
                "KMS_CORE_IMAGE_TAG": "v0.14.0",
                "KMS_CORE_CLIENT_IMAGE_TAG": "v0.14.0",
                "SERVER_URL": "https://github.com",
                "REPOSITORY": "zama-ai/kms",
                "RUN_ID": "123",
                "IMAGE_REPO": "registry/kms",
            },
            clear=True,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)


class RunnerTests(TemporaryWorkingDirectory):
    def test_staged_tools_survive_a_checkout_without_python_tools(self):
        with patch.dict(os.environ, {"RUNNER_TEMP": str(Path("runner-temp").resolve())}):
            runner.stage_tools()
        staged = Path("runner-temp/kms-perf-tools")
        expected = {
            path.name
            for pattern in ("perf_*.py", "sample_*.py", "collect_*.py")
            for path in runner.SCRIPTS.glob(pattern)
        }
        self.assertEqual({path.name for path in staged.glob("*.py")}, expected)
        self.assertIn("PERF_TOOLS_DIR=", Path("github-env").read_text())
        completed = common.run([sys.executable, str(staged / "perf_runner.py"), "--help"])
        self.assertIn("verify-images", completed.stdout)

    def test_staging_includes_new_tools_but_not_unrelated_scripts(self):
        source = Path("source")
        source.mkdir()
        for name in ("perf_extra.py", "sample_extra.py", "collect_extra.py", "analyze_other.py"):
            (source / name).write_text("# fixture\n")
        with (
            patch.object(runner, "SCRIPTS", source),
            patch.dict(os.environ, {"RUNNER_TEMP": str(Path("runner-temp").resolve())}),
        ):
            runner.stage_tools()
        self.assertEqual(
            {path.name for path in Path("runner-temp/kms-perf-tools").glob("*.py")},
            {"perf_extra.py", "sample_extra.py", "collect_extra.py"},
        )

    def test_image_tags_and_environment(self):
        with patch.dict(os.environ, {"DOCKER_BUILD_TAG": "build-123", "INPUT_CORE_TAG": "ignored"}):
            runner.determine_tags()
        self.assertIn("KMS_CORE_CLIENT_IMAGE_TAG=build-123\n", Path("github-env").read_text())
        self.assertIn("build-123", Path("summary").read_text())
        with patch.dict(
            os.environ, {"INPUT_CORE_TAG": "old-core", "INPUT_CLIENT_TAG": "old-client"}
        ):
            runner.determine_tags()
        self.assertIn("KMS_CORE_CLIENT_IMAGE_TAG=old-client", Path("github-env").read_text())
        with self.assertRaises(ValueError):
            runner.determine_tags()

    def test_environment_rejects_newlines_before_writing(self):
        with self.assertRaises(ValueError):
            runner.github_env({"SAFE": "value", "BAD": "value\nINJECTED=yes"})
        self.assertFalse(Path("github-env").exists())

    def test_deployment_validation(self):
        runner.validate()
        self.assertIn("PATH_SUFFIX=kms-ci", Path("github-env").read_text())
        with patch.dict(os.environ, {"TLS": "true"}):
            with self.assertRaises(ValueError):
                runner.validate()
            with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "thresholdWithEnclave"}):
                runner.validate()
        with (
            patch.dict(os.environ, {"DEPLOYMENT_TYPE": "centralized"}),
            self.assertRaises(ValueError),
        ):
            runner.validate()

    @patch.object(runner, "run")
    @patch.object(runner, "best_effort")
    def test_log_collection_selects_container_and_keeps_missing_pod_artifacts(self, get, logs):
        get.side_effect = [result(), *[result(code=1) for _ in range(12)]]

        def capture(args, **kwargs):
            kwargs["stdout"].write("core log\n")
            return result()

        logs.side_effect = capture
        with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "thresholdWithEnclave"}):
            runner.core_logs()
        self.assertIn("kms-core-enclave-logger", logs.call_args.args[0])
        self.assertEqual(Path("kms-core-1-logs.txt").read_text(), "core log\n")
        self.assertEqual(Path("kms-core-13-logs.txt").read_text(), "")

    @patch.object(runner.time, "sleep")
    @patch.object(runner, "best_effort")
    def test_registry_retries_both_images(self, command, sleep):
        command.side_effect = [result(code=1), result(), result()]
        runner.verify_images()
        self.assertEqual(command.call_count, 3)
        sleep.assert_called_once_with(5)
        self.assertIn("core-client-insecure:v0.14.0", command.call_args.args[0][-1])
        command.reset_mock()
        command.side_effect = None
        command.return_value = result(code=1)
        with self.assertRaises(ValueError):
            runner.verify_images()
        self.assertEqual(command.call_count, 24)

    @patch.object(runner.shutil, "which", return_value="gh")
    @patch.object(runner, "best_effort")
    def test_job_link_fallback_and_success(self, command, which):
        command.return_value = result("invalid json")
        self.assertEqual(runner.job_link()[1], "run 123")
        command.return_value = result(
            json.dumps({"jobs": [{"name": "performance-testing", "id": 45, "html_url": "job-url"}]})
        )
        self.assertEqual(runner.job_link(), ("job-url", "job 45"))

    def workflow_command(self, args, **kwargs):
        if args[0] == sys.executable:
            Path(args[-1]).write_text("image: core-client-insecure:<client-version>\n")
            return result()
        if args[1] == "submit":
            self.assertIn("tls=disabled", args)
            return result('{"metadata":{"name":"perf-123"}}')
        if args[1] == "wait":
            return result()
        if args[1] == "logs":
            kwargs["stdout"].write("benchmark log\n")
            return result()
        if args[1] == "get":
            return result('{"status":{"phase":"Succeeded"}}')
        self.fail(f"Unexpected command: {args}")

    @patch.object(runner, "job_link", return_value=("url", "label"))
    def test_workflow_success_keeps_selected_old_image(self, link):
        with patch.object(runner, "run", side_effect=self.workflow_command):
            runner.execute_workflow("kms-ci")
        self.assertEqual(
            Path("perf-workflow.generated.yaml").read_text(),
            "image: core-client-insecure:v0.14.0\n",
        )
        self.assertEqual(Path("argo-workflow-logs.txt").read_text(), "benchmark log\n")
        self.assertIn("PERF_WORKFLOW_NAME=perf-123", Path("github-env").read_text())

    @patch.object(runner, "job_link", return_value=("url", "label"))
    def test_wait_timeout_still_collects_logs(self, link):
        def command(args, **kwargs):
            if args[:2] == ["argo", "wait"]:
                raise subprocess.TimeoutExpired(args, 3600)
            return self.workflow_command(args, **kwargs)

        with (
            patch.object(runner, "run", side_effect=command),
            self.assertRaisesRegex(ValueError, "Timed out"),
        ):
            runner.execute_workflow("kms-ci")
        self.assertEqual(Path("argo-workflow-logs.txt").read_text(), "benchmark log\n")

    @patch.object(runner, "job_link", return_value=("url", "label"))
    def test_failed_phase_and_missing_submit_name(self, link):
        def command(args, **kwargs):
            if args[:2] == ["argo", "get"]:
                return result('{"status":{"phase":"Failed"}}')
            return self.workflow_command(args, **kwargs)

        with (
            patch.object(runner, "run", side_effect=command),
            self.assertRaisesRegex(ValueError, "Failed"),
        ):
            runner.execute_workflow("kms-ci")

        def bad_submit(args, **kwargs):
            if args[:2] == ["argo", "submit"]:
                return result("{}")
            return self.workflow_command(args, **kwargs)

        with (
            patch.object(runner, "run", side_effect=bad_submit),
            self.assertRaisesRegex(ValueError, "no workflow name"),
        ):
            runner.execute_workflow("kms-ci")

    @patch.object(runner, "stop_samplers")
    @patch.object(runner, "start_sampler")
    @patch.object(runner, "execute_workflow")
    def test_samplers_stop_on_failure_and_cancellation(self, execute, start, stop):
        for failure in (ValueError("failed"), KeyboardInterrupt()):
            execute.side_effect = failure
            start.side_effect = ["diagnostics"]
            with self.assertRaises(type(failure)):
                runner.performance()
            stop.assert_called_with(["diagnostics"], process_groups=True)
        start.side_effect = [OSError("start failed")]
        with self.assertRaises(OSError):
            runner.performance()
        stop.assert_called_with([], process_groups=True)

    @patch.object(runner, "best_effort", return_value=result(code=1, stderr="unavailable"))
    def test_cleanup_continues_after_errors_and_skips_unknown_workflow(self, command):
        runner.cleanup()
        args = [call.args[0] for call in command.call_args_list]
        self.assertEqual(len(args), 7)
        self.assertFalse(any(arg[0] == "argo" for arg in args))
        with patch.dict(os.environ, {"PERF_WORKFLOW_NAME": "perf-123"}):
            runner.cleanup()
        self.assertEqual(command.call_args.args[0], ["argo", "delete", "perf-123", "-n", "kms-ci"])

    def test_reports_limit_output_and_allow_missing_files(self):
        runner.report_cpu()
        runner.report_diagnostics()
        Path("core-cpu-samples.log").write_text("".join(f"sample-{i}\n" for i in range(600)))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            runner.report_cpu()
        self.assertNotIn("sample-99\n", output.getvalue())
        self.assertIn("sample-100\n", output.getvalue())
        self.assertIn("600 sample lines", output.getvalue())


class DiagnosticTests(TemporaryWorkingDirectory):
    def test_network_phase_rejects_paths_before_collection(self):
        for phase in ("../outside", "/tmp/outside", "nested/phase", ".", "..", ""):
            with (
                self.subTest(phase=phase),
                patch.object(sys, "argv", ["network", phase]),
                patch.object(network, "collect") as collect,
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as error,
                ):
                    network.main()
                self.assertEqual(error.exception.code, 2)
                collect.assert_not_called()
        with (
            patch.object(sys, "argv", ["network", "before-perf", "ns"]),
            patch.object(network, "collect") as collect,
        ):
            network.main()
            collect.assert_called_once_with("before-perf", "ns", Path("network-diagnostics"))

    @patch.object(metrics, "timestamp", return_value="stamp")
    @patch.object(metrics, "scrape_pod", return_value=["sample"])
    @patch.object(
        metrics, "best_effort", return_value=result("pod-a\t10.0.0.1\npod-b\t\n\npod-c\n")
    )
    def test_scrape_discovery_preserves_pods_without_ips(self, command, scrape, stamp):
        metrics.scrape_once("ns", 9646, 4)
        self.assertCountEqual(
            [call.args for call in scrape.call_args_list],
            [
                ("ns", "stamp", "pod-a", "10.0.0.1", 9646, 4),
                ("ns", "stamp", "pod-b", "", 9646, 4),
                ("ns", "stamp", "pod-c", "", 9646, 4),
            ],
        )

    @patch.object(metrics.time, "sleep", side_effect=AssertionError("--once must not loop"))
    @patch.object(metrics, "scrape_once")
    def test_scrape_once_takes_a_single_snapshot(self, scrape, sleep):
        with patch.object(sys, "argv", ["metrics", "ns", "--once"]):
            metrics.main()
        scrape.assert_called_once_with("ns", 9646, 4.0)
        sleep.assert_not_called()

    def test_network_deltas_preserve_missing_and_reset_counter_semantics(self):
        row = dict(zip(network.HEADER, ["p", "c", "eth0", "9001", *(["10"] * 8)]))
        after = dict(row, rx_bytes="25", tx_bytes="2")
        delta = network.counter_deltas([row], [after])[0]
        self.assertEqual((delta["rx_bytes"], delta["tx_bytes"]), (15, -8))
        self.assertEqual(network.counter_deltas([], [after])[0]["rx_bytes"], 25)
        Path("before").write_text("captured_at=2026-01-01T00:00:00Z\n")
        Path("after").write_text("captured_at=2026-01-01T00:00:10Z\n")
        self.assertEqual(network.elapsed(Path("before"), Path("after")), 10)
        self.assertEqual(network.elapsed(Path("missing"), Path("after")), 0)

    @patch.object(network, "kube_json")
    @patch.object(network, "best_effort")
    def test_network_artifacts(self, command, pods):
        pods.return_value = {
            "items": [
                {
                    "metadata": {"name": "kms-core-1-core-1"},
                    "spec": {"containers": [{"name": "kms-core"}]},
                    "status": {"phase": "Running"},
                }
            ]
        }

        def capture(args, **kwargs):
            return (
                result("kms-core-1-core-1\tkms-core\teth0\t9001\t" + "10\t" * 8 + "\n")
                if args[1] == "exec"
                else result()
            )

        command.side_effect = capture
        network.collect("before-perf", "kms-ci", Path("network"))
        network.collect("after-perf", "kms-ci", Path("network"))
        rows = network.read_rows(Path("network/pod-interface-counter-delta.tsv"))
        self.assertEqual(rows[0]["rx_bytes"], "0")
        self.assertEqual(rows[0]["pod"], "kms-core-1-core-1")

    @patch.object(cpu, "timestamp", return_value="stamp")
    @patch.object(cpu, "best_effort", return_value=result("pod-1 20m 10Mi\n"))
    def test_cpu_artifact(self, command, stamp):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            cpu.sample("kms-ci")
        self.assertEqual(output.getvalue(), "stamp pod-1 20m 10Mi\n")

    def test_metrics_filter_and_missing_diagnostics(self):
        text = (
            "# HELP ignored\n"
            "kms_completed_sessions 12\n"
            "kms_completed_sessions_extra 9\n"
            'kms_operations_total{operation="user_decrypt_request"} 4\n'
            'kms_operations_total{operation="keygen"} 6\n'
            'kms_operation_duration_ms_bucket{operation_type="public_decrypt_result",le="1"} 3'
        )
        selected, missing = metrics.extract_metrics(text, "stamp", "pod")
        self.assertEqual(len(selected), 3)
        self.assertEqual(selected[0], "stamp pod kms_completed_sessions 12")
        self.assertNotIn("kms_completed_sessions", missing)
        self.assertIn("kms_tokio_alive_tasks", missing)

    @patch.object(metrics, "best_effort")
    def test_scrape_proxy_fallback_and_failure(self, command):
        command.side_effect = [result(code=1), result("kms_completed_sessions 1\n")]
        lines = metrics.scrape_pod("ns", "stamp", "pod", "10.0.0.1", 9646, 4)
        self.assertIn("method=pod-proxy", lines[0])
        self.assertIn(
            "/api/v1/namespaces/ns/pods/pod:9646/proxy/metrics", command.call_args.args[0]
        )
        command.side_effect = [result(code=1, stderr="failed\nrequest")]
        self.assertEqual(
            metrics.scrape_pod("ns", "stamp", "pod", "", 9646, 4),
            ['stamp pod scrape_error error="failed request"'],
        )

    def test_placement_requires_complete_cluster_and_joins_endpoints(self):
        pods = [
            {
                "metadata": {"name": f"core-{i}", "labels": {"app": "kms-core"}},
                "spec": {"nodeName": "node"},
            }
            for i in range(13)
        ]
        self.assertEqual(placement.placement_rows({"items": pods}, {}, "stamp"), [])
        pods.append(
            {
                "metadata": {"name": "client", "labels": {"test": "udec-rate-2400"}},
                "spec": {"nodeName": "node"},
            }
        )
        slices = {
            "items": [
                {
                    "endpoints": [
                        {
                            "nodeName": "node",
                            "zone": "eu-a",
                            "deprecatedTopology": {
                                "node.kubernetes.io/instance-type": "c6in.32xlarge"
                            },
                        }
                    ]
                }
            ]
        }
        rows = placement.placement_rows({"items": pods}, slices, "stamp")
        self.assertEqual(len(rows), 14)
        self.assertEqual(rows[-1][3:6], ["node", "eu-a", "c6in.32xlarge"])
        self.assertEqual(placement.placement_rows({"items": pods}, {}, "stamp")[0][4], "-")

    def test_lifecycle_handles_pending_pods(self):
        rows = diagnostics.lifecycle_rows(
            {"metadata": {"creationTimestamp": "created"}},
            {"items": [{"metadata": {"name": "probe"}, "status": {"phase": "Pending"}}]},
            "stamp",
        )
        self.assertEqual(rows[0][3:], [0, 0, 0, 0])
        self.assertEqual(rows[1][7:], [False, 0, "", "", ""])
        self.assertIn("\tfalse\t", common.tsv(rows[1]))

    @patch.object(diagnostics, "finish")
    @patch.object(diagnostics, "stop_samplers")
    @patch.object(diagnostics, "start_sampler", side_effect=["cpu", OSError("start failed")])
    @patch.object(diagnostics, "best_effort", return_value=result())
    def test_controller_finalizes_after_partial_start(self, command, start, stop, finish):
        with self.assertRaises(OSError):
            diagnostics.sample("ns", Path("diagnostics"))
        stop.assert_called_once_with(["cpu"])
        finish.assert_called_once_with("ns", Path("diagnostics"))

    @patch.object(diagnostics, "finish")
    @patch.object(diagnostics, "stop_samplers")
    @patch.object(diagnostics, "start_sampler", side_effect=["cpu", "metrics", "placement"])
    @patch.object(diagnostics, "best_effort", return_value=result())
    @patch.object(diagnostics, "kube_json", return_value={})
    @patch.object(diagnostics.time, "sleep", side_effect=KeyboardInterrupt())
    def test_controller_stops_all_samplers_on_cancellation(
        self, sleep, kube, command, start, stop, finish
    ):
        with self.assertRaises(KeyboardInterrupt):
            diagnostics.sample("ns", Path("diagnostics"))
        self.assertEqual(
            start.call_args_list[0].args,
            (
                "sample_core_cpu.py",
                ["ns"],
                "core-cpu-samples.log",
            ),
        )
        stop.assert_called_once_with(["cpu", "metrics", "placement"])
        finish.assert_called_once_with("ns", Path("diagnostics"))


class ProcessTests(unittest.TestCase):
    def test_tsv_escapes_backslashes_before_control_characters(self):
        self.assertEqual(
            common.tsv(["literal\\t\tline\nnext\r", None, False, True, 3]),
            "literal\\\\t\\tline\\nnext\\r\t\tfalse\ttrue\t3",
        )

    def test_cli_reports_missing_environment(self):
        def missing():
            raise KeyError("RUNNER_TEMP")

        with (
            patch.object(common.signal, "signal"),
            contextlib.redirect_stderr(io.StringIO()) as output,
            self.assertRaises(SystemExit) as error,
        ):
            common.cli(missing)
        self.assertEqual(error.exception.code, 1)
        self.assertIn("::error::Missing required value: 'RUNNER_TEMP'", output.getvalue())

    def test_group_exit_race_does_not_replace_original_error(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("sampler", 300), 0]
        with (
            patch.object(common.os, "killpg", side_effect=ProcessLookupError),
            self.assertRaisesRegex(ValueError, "original failure"),
        ):
            try:
                raise ValueError("original failure")
            finally:
                common.stop_samplers([process], process_groups=True)

    def test_forced_group_cleanup_closes_descendant_output(self):
        # The inherited pipe stays open if either descendant survives group cleanup.
        grandchild = "import time; time.sleep(60)"
        child = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
            "print('ready', flush=True); time.sleep(60)"
        )
        parent = (
            "import signal, subprocess, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(60)"
        )
        with subprocess.Popen(
            [sys.executable, "-c", parent],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        ) as process:
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, "sampler tree did not start")
                self.assertEqual(process.stdout.readline(), "ready\n")
                with patch.object(common, "SAMPLER_STOP_TIMEOUT", 0.1):
                    common.stop_samplers([process], process_groups=True)
                process.communicate(timeout=5)
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    def test_cancellation_terminates_active_command(self):
        process = Mock()
        process.__enter__ = Mock(return_value=process)
        process.__exit__ = Mock(return_value=False)
        process.communicate.side_effect = [KeyboardInterrupt(), ("", "")]
        with (
            patch.object(common.subprocess, "Popen", return_value=process),
            self.assertRaises(KeyboardInterrupt),
        ):
            common.run(["fake-command"])
        process.terminate.assert_called_once()
        self.assertEqual(process.communicate.call_count, 2)

    def test_command_arguments_are_not_shell_source(self):
        text = 'literal $(exit 99); "quoted"'
        completed = common.run([sys.executable, "-c", "import sys; print(sys.argv[1])", text])
        self.assertEqual(completed.stdout, text + "\n")

    def test_timeout_reaps_child(self):
        real_popen = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with (
            patch.object(common.subprocess, "Popen", side_effect=spawn),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            common.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.1)
        self.assertIsNotNone(children[0].poll())

    def test_stop_requests_all_children_before_waiting(self):
        events = []
        children = []
        for name in ("cpu", "diagnostics"):
            child = Mock()
            child.poll.return_value = None
            child.terminate.side_effect = lambda name=name: events.append(f"stop {name}")
            child.wait.side_effect = lambda timeout, name=name: events.append(f"wait {name}")
            children.append(child)
        common.stop_samplers(children)
        self.assertEqual(events, ["stop cpu", "stop diagnostics", "wait cpu", "wait diagnostics"])


if __name__ == "__main__":
    unittest.main()
