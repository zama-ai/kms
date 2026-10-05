"""Tests for the nightly Slack summary."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nightly_slack_summary as summary

RUN_URL = "https://github.com/zama-ai/kms/actions/runs/1"


def job(name, conclusion):
    return {"name": name, "conclusion": conclusion, "html_url": f"https://job/{name}"}


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
            "main/test-workspace-crates (crates-heavy-2-dkg)",
        )

    def test_keeps_single_value_matrix_suffix(self):
        self.assertEqual(summary.short_name("main/x (a)"), "main/x (a)")

    def test_keeps_plain_name(self):
        self.assertEqual(summary.short_name("main/check-changes"), "main/check-changes")


class BuildPayloadTest(unittest.TestCase):
    def test_lists_failures_first_and_omits_unfinished_jobs(self):
        payload = summary.build_payload(
            [
                job("main/a", "success"),
                job("main/b", "cancelled"),
                job("main/c", "skipped"),
                job("main/d", "failure"),
                job("main/notify", None),
            ],
            RUN_URL,
        )
        self.assertEqual(payload["color"], "danger")
        self.assertEqual(
            payload["text"].splitlines(),
            [
                f"<{RUN_URL}|Nightly run>: 2 of 3 jobs did not succeed.",
                "",
                ":x: <https://job/main/d|main/d> (failure)",
                ":no_entry_sign: <https://job/main/b|main/b> (cancelled)",
                ":white_check_mark: <https://job/main/a|main/a>",
            ],
        )

    def test_all_success_is_good(self):
        payload = summary.build_payload([job("main/a", "success")], RUN_URL)
        self.assertEqual(payload["color"], "good")
        self.assertTrue(
            payload["text"].startswith(
                f"<{RUN_URL}|Nightly run>: all 1 jobs succeeded."
            )
        )

    def test_no_finished_jobs_is_danger(self):
        self.assertEqual(summary.build_payload([], RUN_URL)["color"], "danger")


if __name__ == "__main__":
    unittest.main()
