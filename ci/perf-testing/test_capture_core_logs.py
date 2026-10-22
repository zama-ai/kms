#!/usr/bin/env python3
"""Exercise per-party log failure and bounded collector shutdown without a cluster."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


class CaptureLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def start_capture(self, exit_status="running", ignore_term=False):
        environment_file = self.directory / "kubectl-stub.sh"
        environment_file.write_text('''kubectl() {
  if [ "$CAPTURE_IGNORE_TERM" = 1 ]; then trap '' TERM; else trap 'exit 0' TERM; fi
  printf '%s\\n' "$BASHPID" >> "$CAPTURE_CHILD_PIDS"
  case "$*" in
    *kms-core-1-core-1*)
      if [ "$CAPTURE_FIRST_STATUS" != running ]; then
        sleep 0.1
        return "$CAPTURE_FIRST_STATUS"
      fi
      ;;
  esac
  while :; do sleep 0.1; done
}
''')
        self.pid_file = self.directory / "children"
        environment = dict(os.environ, BASH_ENV=str(environment_file), NUM_PARTIES="2", NAMESPACE="test",
                           RUN=str(self.directory / "logs"), CLEANUP_TIMEOUT_SECONDS="1",
                           CAPTURE_CHILD_PIDS=str(self.pid_file), CAPTURE_FIRST_STATUS=exit_status,
                           CAPTURE_IGNORE_TERM="1" if ignore_term else "0")
        process = subprocess.Popen(["bash", str(Path(__file__).with_name("manual-capture-core-logs.sh"))],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)

        def cleanup_process_group():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=3)

        self.addCleanup(cleanup_process_group)
        return process

    def wait_for_children(self, process):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.pid_file.exists() and len(self.pid_file.read_text().splitlines()) == 2:
                return
            if process.poll() is not None:
                break
            time.sleep(0.01)
        self.fail("both mocked log streamers did not start")

    def assert_children_reaped(self):
        for pid in self.pid_file.read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid), 0)

    def test_unexpected_clean_child_exit_rejects_capture(self):
        process = self.start_capture(exit_status="0")
        self.wait_for_children(process)
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 1, stderr)
        self.assertIn("party 1 log streamer exited unexpectedly (status 0)", stderr)
        self.assert_children_reaped()

    def test_failed_child_rejects_capture_and_stops_other_party(self):
        process = self.start_capture(exit_status="23")
        self.wait_for_children(process)
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 1, stderr)
        self.assertIn("party 1 log streamer exited unexpectedly (status 23)", stderr)
        self.assert_children_reaped()

    def test_intentional_term_stops_and_reaps_all_children(self):
        process = self.start_capture()
        self.wait_for_children(process)
        process.terminate()
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertNotIn("unexpectedly", stderr)
        self.assert_children_reaped()

    def test_shutdown_kills_unresponsive_children_within_bound(self):
        process = self.start_capture(ignore_term=True)
        self.wait_for_children(process)
        started = time.monotonic()
        process.terminate()
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertLess(time.monotonic() - started, 3)
        self.assert_children_reaped()


if __name__ == "__main__":
    unittest.main()
