"""Regression tests for benchmark fleet admission and continuity."""

import copy
import unittest

from verify_bench_state import check_continuity, check_reference, validate


class FleetValidationTests(unittest.TestCase):
    def setUp(self):
        self.name = "kms-core-1-core-1"
        self.pods = {"items": [{
            "metadata": {"name": self.name, "uid": "uid-1"},
            "spec": {"nodeName": "node-1", "volumes": [{"configMap": {"name": "config-1"}}],
                     "containers": [{"name": "kms-core", "resources": {"limits": {"cpu": "2"}}}]},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"name": "kms-core", "imageID": "sha256:abc", "restartCount": 0,
                                       "state": {"running": {"startedAt": "2026-10-22T10:00:00Z"}}}],
            },
        }]}
        self.configs = {"items": [{"metadata": {"name": "config-1"}, "data": {"kms-server.toml":
            "[internal_config]\nnum_tokio_threads = 10\nnum_rayon_threads = 60\n"
            "[threshold]\nnum_sessions_preproc = 90\n"}}]}
        self.logs = {self.name: "benchmark runtime: tokio=10 rayon=60 preproc=90\n"
                     "tuning: exporting MPC_DKG_PRSS_PIPELINE=0 into the process environment\n"}

    def fleet(self):
        return validate(self.pods, self.configs, self.logs, 1, 10, 60, 90, "MPC_DKG_PRSS_PIPELINE=0")

    def test_ready_configured_fleet_is_accepted(self):
        fleet = self.fleet()
        self.assertEqual(fleet[self.name]["node"], "node-1")
        check_continuity(fleet, copy.deepcopy(fleet))

    def test_missing_party_and_unready_party_are_rejected(self):
        original = copy.deepcopy(self.pods)
        self.pods["items"] = []
        with self.assertRaisesRegex(ValueError, "expected party pods"):
            self.fleet()
        self.pods = original
        self.pods["items"][0]["status"]["conditions"][0]["status"] = "False"
        with self.assertRaisesRegex(ValueError, "not Ready"):
            self.fleet()

    def test_stale_runtime_and_extra_export_are_rejected(self):
        self.logs[self.name] = self.logs[self.name].replace("tokio=10", "tokio=24")
        with self.assertRaisesRegex(ValueError, "startup"):
            self.fleet()
        self.logs[self.name] = self.logs[self.name].replace("tokio=24", "tokio=10")
        self.logs[self.name] += "tuning: exporting MPC_C2C_CONNECTIONS_PER_PEER=4 into the process environment\n"
        with self.assertRaisesRegex(ValueError, "exports differ"):
            self.fleet()

    def test_config_change_and_container_restart_are_rejected(self):
        before = self.fleet()
        self.configs["items"][0]["data"]["kms-server.toml"] += "# changed\n"
        with self.assertRaisesRegex(ValueError, "changed during measurement"):
            check_continuity(before, self.fleet())
        self.configs["items"][0]["data"]["kms-server.toml"] = self.configs["items"][0]["data"]["kms-server.toml"].replace("# changed\n", "")
        self.pods["items"][0]["status"]["containerStatuses"][0]["restartCount"] = 1
        with self.assertRaisesRegex(ValueError, "changed during measurement"):
            check_continuity(before, self.fleet())

    def test_missing_digest_is_rejected(self):
        del self.pods["items"][0]["status"]["containerStatuses"][0]["imageID"]
        with self.assertRaisesRegex(ValueError, "missing image identity"):
            self.fleet()

    def test_reference_allows_restarts_and_tuning_but_not_environment_drift(self):
        before = self.fleet()
        after = copy.deepcopy(before)
        after[self.name]["uid"] = "new-uid"
        after[self.name]["config_sha256"] = "different-tuning"
        after[self.name]["containers"]["kms-core"]["started_at"] = "later"
        check_reference(before, after)
        for key in ("image_id", "runtime_spec_sha256"):
            changed = copy.deepcopy(after)
            changed[self.name]["containers"]["kms-core"][key] = "changed"
            with self.assertRaisesRegex(ValueError, "REFERENCE_FLEET"):
                check_reference(before, changed)
        for key in ("node", "enclave_config_sha256"):
            changed = copy.deepcopy(after)
            changed[self.name][key] = "changed"
            with self.assertRaisesRegex(ValueError, "REFERENCE_FLEET"):
                check_reference(before, changed)

    def test_resources_and_missing_sidecar_status_are_checked(self):
        before = self.fleet()
        self.pods["items"][0]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "4"
        with self.assertRaisesRegex(ValueError, "runtime_spec"):
            check_reference(before, self.fleet())
        self.pods["items"][0]["spec"]["initContainers"] = [{"name": "tunnel"}]
        with self.assertRaisesRegex(ValueError, "status inventory"):
            self.fleet()


if __name__ == "__main__":
    unittest.main()
