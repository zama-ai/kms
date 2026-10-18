"""Regression tests for the deploy.sh argument handling in lib/common.sh."""

import subprocess
import unittest
from pathlib import Path

COMMON_SH = Path(__file__).resolve().parents[1] / "lib" / "common.sh"


def parse_args(*args):
    script = 'source "$0"; shift; parse_args "$@"; echo "${DEPLOYMENT_TYPE}"'
    return subprocess.run(
        ["bash", "-c", script, str(COMMON_SH), "--", *args],
        capture_output=True,
        text=True,
        check=False,
    )


class DeploymentTypeTest(unittest.TestCase):
    def test_threshold_types_are_accepted(self):
        for deployment in ("threshold", "thresholdWithEnclave"):
            with self.subTest(deployment=deployment):
                proc = parse_args("--deployment-type", deployment)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(proc.stdout.strip().splitlines()[-1], deployment)

    def test_centralized_types_are_rejected(self):
        for deployment in ("centralized", "centralizedWithEnclave"):
            with self.subTest(deployment=deployment):
                proc = parse_args("--deployment-type", deployment)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("threshold mode only", proc.stdout)

    def test_unknown_type_is_rejected(self):
        proc = parse_args("--deployment-type", "thresholdish")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Unknown deployment type", proc.stdout)


if __name__ == "__main__":
    unittest.main()
