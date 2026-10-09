"""Tests for the nightly Slack summary."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nightly_slack_summary as summary

RUN_URL = "https://github.com/zama-ai/kms/actions/runs/1"


def job(name, conclusion, status="completed", runner_name="runner-1"):
    return {
        "name": name,
        "conclusion": conclusion,
        "status": status,
        "runner_name": runner_name,
        "html_url": f"https://job/{name}",
    }


class ShortNameTest(unittest.TestCase):
    def test_strips_caller_and_common_testing_segments(self):
        self.assertEqual(
            summary.short_name(
                "main/rust-testing / rust-testing/core-grpc-p1 / common-testing/compile-rust-unit-tests"
            ),
            "rust-testing/core-grpc-p1",
        )

    def test_reduces_matrix_suffix_to_first_value(self):
        self.assertEqual(
            summary.short_name(
                "main/test-workspace-crates (crates-heavy-2-dkg, -p threshold-bgv, "
                "-E test(/test_dkg_with_offline/), 2, 64cpu-linux-x64) "
                "/ common-testing/compile-rust-unit-tests"
            ),
            "test-workspace-crates (crates-heavy-2-dkg)",
        )

    def test_keeps_single_value_matrix_suffix(self):
        self.assertEqual(summary.short_name("main/x (a)"), "x (a)")

    def test_strips_main_prefix_from_plain_name(self):
        self.assertEqual(summary.short_name("main/check-changes"), "check-changes")


class BuildPayloadTest(unittest.TestCase):
    def test_lists_unsuccessful_jobs_failures_first(self):
        payload = summary.build_payload(
            [
                job("main/a", "success"),
                job("main/b", "cancelled"),
                job("main/c", "skipped"),
                job("main/d", "failure"),
                job("main/late", None, "in_progress", "runner-2"),
                job("main/notify", None, "in_progress", "own-runner"),
            ],
            RUN_URL,
            "own-runner",
        )
        self.assertEqual(payload["color"], "danger")
        self.assertEqual(
            payload["text"].splitlines(),
            [
                f"<{RUN_URL}|Nightly run>: 1 succeeded, 3 did not succeed, 1 skipped.",
                "",
                ":x: <https://job/main/d|d> (failure)",
                ":no_entry_sign: <https://job/main/b|b> (cancelled)",
                ":hourglass_flowing_sand: <https://job/main/late|late> (in_progress)",
            ],
        )

    def test_escapes_reserved_characters_in_name(self):
        payload = summary.build_payload(
            [job("main/a <b> & c", "failure")], RUN_URL, "own-runner"
        )
        self.assertIn("|a &lt;b&gt; &amp; c>", payload["text"])

    def test_all_success_is_one_good_line(self):
        payload = summary.build_payload(
            [job("main/a", "success"), job("main/b", "skipped")], RUN_URL, "own-runner"
        )
        self.assertEqual(payload["color"], "good")
        self.assertEqual(
            payload["text"],
            f"<{RUN_URL}|Nightly run>: 1 succeeded, 0 did not succeed, 1 skipped.",
        )

    def test_no_reported_jobs_is_danger(self):
        payload = summary.build_payload([], RUN_URL, "own-runner")
        self.assertEqual(payload["color"], "danger")
        self.assertEqual(
            payload["text"],
            f"<{RUN_URL}|Nightly run>: 0 succeeded, 0 did not succeed, 0 skipped.",
        )


if __name__ == "__main__":
    unittest.main()
