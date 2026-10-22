#!/usr/bin/env python3
"""Regression tests for benchmark windows, counter validity, and comparisons."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("analyse_run", Path(__file__).with_name("analyse_run.py"))
analyse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analyse)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def snapshot(self, epoch, body, party=1, identity=50, root=None):
        directory = (root or self.directory) / "raw" / f"p{party}"
        directory.mkdir(parents=True, exist_ok=True)
        prefix = "kms_total_cpus 52\n"
        if 'kind="bits"' not in body:
            prefix += 'kms_dkg_generated_items_total{kind="bits"} 0\n'
        if 'kind="triples"' not in body:
            prefix += 'kms_dkg_generated_items_total{kind="triples"} 0\n'
        if identity is not None:
            prefix += f"kms_process_start_time_seconds {identity}\n"
        (directory / f"{epoch}.prom").write_text(prefix + body)
        return directory

    def summarize(self, manifest, root=None, stop_pct=25):
        root = root or self.directory
        (root / "manifest.json").write_text(json.dumps(manifest))
        with contextlib.redirect_stdout(io.StringIO()):
            return analyse.summarize(str(root), stop_pct, None)

    def test_lazy_labels_have_zero_initial_value_with_stable_process(self):
        raw = self.snapshot(100, "")
        self.snapshot(200, 'kms_optimistic_reconstruct_total{site="d_values",outcome="hit"} 100\n'
                      'kms_c2c_send_rpc_duration_ms_count{size_bucket="le_16m"} 10\n'
                      'kms_c2c_send_rpc_duration_ms_sum{size_bucket="le_16m"} 20000\n'
                      'kms_c2c_send_rpc_duration_ms_bucket{size_bucket="le_16m",le="2500"} 10\n')
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["optimistic"]["d_values"]["hit_pct"], 100)
        self.assertEqual(result["rpc"]["le_16m"]["avg_ms"], 2000)
        self.assertEqual(result["rpc"]["le_16m"]["p95_ms_upper_bound"], 2500)

    def test_unsupported_metrics_remain_absent(self):
        raw = self.snapshot(100, "", identity=None)
        self.snapshot(200, "", identity=None)
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["status"], "exploratory")
        self.assertEqual(result["optimistic"], {})
        self.assertEqual(result["rpc"], {})

    def test_counter_reset_between_endpoints_invalidates_window(self):
        raw = self.snapshot(100, "kms_network_tx_bytes_total 100\n")
        self.snapshot(150, "kms_network_tx_bytes_total 10\n")
        self.snapshot(200, "kms_network_tx_bytes_total 300\n")
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["status"], "invalid")
        self.assertNotIn("tx_gbps", result)

    def test_process_restart_invalidates_even_monotone_counters(self):
        raw = self.snapshot(100, "kms_network_tx_bytes_total 100\n")
        self.snapshot(200, "kms_network_tx_bytes_total 300\n", identity=150)
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["status"], "invalid")
        self.assertIn("process identity changed", result["invalid_reasons"][0])

    def test_disappearing_counter_invalidates_window(self):
        raw = self.snapshot(100, "kms_network_tx_bytes_total 100\n")
        self.snapshot(200, "")
        self.assertEqual(analyse.summarise_party_metrics(str(raw))["status"], "invalid")

    def test_cutoff_excludes_warmup_and_teardown_reset(self):
        raw = self.snapshot(100.25, "kms_network_tx_bytes_total 0\n")
        self.snapshot(150.25, "kms_network_tx_bytes_total 100\n")
        self.snapshot(200.25, "kms_network_tx_bytes_total 200\n")
        self.snapshot(210.25, "kms_network_tx_bytes_total 0\n", identity=205)
        result = analyse.summarise_party_metrics(str(raw), 140, 205)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["first_epoch"], 150.25)
        self.assertEqual(result["last_epoch"], 200.25)
        self.assertEqual(result["window_s"], 50)

    def test_irregular_scrapes_weight_gauges_and_counter_rates_by_duration(self):
        raw = self.snapshot(100, 'kms_thread_pool_cpu_usage{pool="tokio"} 0\nkms_network_tx_bytes_total 0\n')
        self.snapshot(110, 'kms_thread_pool_cpu_usage{pool="tokio"} 100\nkms_network_tx_bytes_total 1000\n')
        self.snapshot(200, 'kms_thread_pool_cpu_usage{pool="tokio"} 999\nkms_network_tx_bytes_total 2000\n')
        result = analyse.summarise_party_metrics(str(raw))
        self.assertAlmostEqual(result["tokio_cores"], 0.9)
        self.assertAlmostEqual(result["tx_gbps"], 2000 * 8 / 100 / 1e9)

    def test_completed_items_and_process_cpu_use_same_window(self):
        raw = self.snapshot(100, 'kms_dkg_generated_items_total{kind="bits"} 100\n'
                           'kms_dkg_generated_items_total{kind="triples"} 10\nkms_process_cpu_seconds_total 20\n')
        self.snapshot(200, 'kms_dkg_generated_items_total{kind="bits"} 1100\n'
                      'kms_dkg_generated_items_total{kind="triples"} 110\nkms_process_cpu_seconds_total 70\n')
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["generated"]["bits"]["items_per_s"], 10)
        self.assertEqual(result["generated"]["triples"]["items_per_s"], 1)
        self.assertEqual(result["generated"]["bits"]["workload_cpu_seconds_per_item"], 0.05)

    def test_missing_expected_party_invalidates_summary(self):
        self.snapshot(100, "")
        self.snapshot(200, "")
        result = self.summarize({"status": "valid", "measurement_start_epoch": 90,
                                 "measurement_end_epoch": 205, "watched_parties": [1, 2]})
        self.assertEqual(result["row"]["status"], "invalid")
        self.assertIn("parties [2]", result["row"]["invalid_reason"])
        self.assertTrue((self.directory / "summary.json").exists())
        self.assertFalse((self.directory / "summary.csv").exists())

    def test_legacy_capture_is_exploratory(self):
        result = self.summarize({})
        self.assertEqual(result["row"]["status"], "exploratory")

    def test_windowed_summary_preserves_valid_status_and_exact_counter_rates(self):
        self.snapshot(100, 'kms_dkg_generated_items_total{kind="bits"} 0\n')
        self.snapshot(150, 'kms_dkg_generated_items_total{kind="bits"} 500\n')
        self.snapshot(200, 'kms_dkg_generated_items_total{kind="bits"} 1000\n')
        self.snapshot(210, 'kms_dkg_generated_items_total{kind="bits"} 0\n', identity=205)
        result = self.summarize({"status": "valid", "measurement_start_epoch": 90,
                                 "measurement_end_epoch": 205, "warmup_seconds": 50, "watched_parties": [1]})
        self.assertEqual(result["row"]["status"], "valid")
        self.assertEqual(result["row"]["bits_per_s_min"], 10)
        self.assertEqual(result["metrics"][1]["first_epoch"], 150)

    def test_progress_cutoff_excludes_later_workload(self):
        path = self.directory / "core-1.log"
        path.write_text("1970-01-01T00:02:30Z Progress TripleGen:\n"
                        "1970-01-01T00:02:30Z Total: 1000\n"
                        "1970-01-01T00:02:30Z Percentage done: 15\n"
                        "1970-01-01T00:02:30Z Time elapsed (s): 150\n"
                        "1970-01-01T00:05:00Z Progress TripleGen:\n"
                        "1970-01-01T00:05:00Z Percentage done: 25\n"
                        "1970-01-01T00:05:00Z Time elapsed (s): 250\n")
        parsed = analyse.parse_core_log(str(path), 0, 200)
        self.assertEqual(analyse.latest_progress(parsed)["TripleGen"][:2], (15, 150))

    def test_nested_details_do_not_enter_phase_denominator(self):
        raw = self.snapshot(100, 'kms_dkg_phase_duration_microseconds_total{phase="prss"} 0\n'
                           'kms_dkg_phase_observations_total{phase="prss"} 0\n')
        self.snapshot(200, 'kms_dkg_phase_duration_microseconds_total{phase="prss"} 1000000\n'
                      'kms_dkg_phase_observations_total{phase="prss"} 1\n'
                      'kms_dkg_detail_duration_seconds_total{operation="rayon_queue"} 9\n'
                      'kms_dkg_detail_observations_total{operation="rayon_queue"} 1\n')
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["phases"]["prss"]["share"], 100)
        self.assertEqual(result["details"]["rayon_queue"]["avg_ms"], 9000)

    def test_schema_two_rejects_large_scrape_gap(self):
        for epoch in (100, 110, 190, 200):
            self.snapshot(epoch, "")
        result = self.summarize({"schema_version": 2, "status": "valid", "measurement_start_epoch": 100,
                                 "measurement_end_epoch": 200, "scrape_interval_seconds": 10, "watched_parties": [1]})
        self.assertEqual(result["row"]["status"], "invalid")
        self.assertIn("scrape gap is 80.000s", result["row"]["invalid_reason"])
        self.assertEqual(result["rejected_metrics"][1]["max_scrape_gap_s"], 80)

    def test_schema_two_rejects_short_observed_interval(self):
        self.snapshot(180, "")
        self.snapshot(190, "")
        result = self.summarize({"schema_version": 2, "status": "valid", "measurement_start_epoch": 100,
                                 "measurement_end_epoch": 300, "scrape_interval_seconds": 10, "watched_parties": [1]})
        self.assertEqual(result["row"]["status"], "invalid")
        self.assertIn("first scrape is 80.000s", result["row"]["invalid_reason"])
        self.assertIn("last scrape is 110.000s", result["row"]["invalid_reason"])

    def test_schema_two_accepts_complete_interval_coverage(self):
        for epoch in (110, 130, 150, 170, 190):
            self.snapshot(epoch, "")
        result = self.summarize({"schema_version": 2, "status": "valid", "measurement_start_epoch": 100,
                                 "measurement_end_epoch": 200, "scrape_interval_seconds": 10, "watched_parties": [1]})
        self.assertEqual(result["row"]["status"], "valid")
        self.assertEqual(result["metrics"][1]["coverage"]["max_allowed_gap_s"], 30)

    def test_both_generated_counters_are_required_for_valid_metrics(self):
        raw = self.snapshot(100, "")
        self.snapshot(200, "")
        for path in raw.glob("*.prom"):
            path.write_text(path.read_text().replace('kms_dkg_generated_items_total{kind="triples"} 0\n', ""))
        result = analyse.summarise_party_metrics(str(raw))
        self.assertEqual(result["status"], "exploratory")
        self.assertIn("triples", result["warnings"][-1])

    def test_disabled_optimistic_calls_do_not_enter_hit_denominator(self):
        raw = self.snapshot(100, "")
        self.snapshot(200, 'kms_optimistic_reconstruct_total{site="d_values",outcome="disabled"} 90\n'
                      'kms_optimistic_reconstruct_total{site="d_values",outcome="hit"} 10\n')
        result = analyse.summarise_party_metrics(str(raw))["optimistic"]["d_values"]
        self.assertEqual(result["disabled"], 90)
        self.assertEqual(result["hit_pct"], 100)

    def test_top_parser_accepts_bare_and_prefixed_timestamps(self):
        path = self.directory / "top-party1.log"
        path.write_text("1970-01-01T00:02:00Z\nparty logger 100m 20Mi\n"
                        "## 1970-01-01T00:02:30Z\nparty logger 200m 30Mi\n"
                        "1970-01-01T00:04:00Z\nparty logger 900m 99Mi\n")
        result = analyse.parse_top_log(str(path), 100, 200)
        self.assertEqual(result["logger"]["samples"], 2)
        self.assertEqual(result["logger"]["cpu_m_mean"], 150)

    def test_common_progress_targets_include_fifteen(self):
        for tag, reached_25 in (("a", True), ("b", False)):
            directory = self.directory / tag
            directory.mkdir()
            row = {"tag": tag, "status": "valid", "triplegen_t10_s": 100,
                   "triplegen_t15_s": 150, "triplegen_t25_s": 250 if reached_25 else None}
            (directory / "summary.json").write_text(json.dumps({"row": row}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rows = analyse.compare(str(self.directory), str(self.directory / "summary.csv"))
        self.assertEqual(len(rows), 2)
        self.assertIn("triplegen_t15_s", output.getvalue())
        self.assertNotIn("triplegen_t25_s", output.getvalue())
        self.assertTrue((self.directory / "summary.csv").exists())

    def test_bandwidth_requires_complete_acknowledged_aggregate(self):
        aggregate = {"status": "complete", "completed_sessions": 1, "requested_sessions": 1,
                     "acknowledged_bytes": 1000000000, "attempts": 10, "successes": 10,
                     "timeouts": 0, "errors": 0, "elapsed_s": 2}
        result = analyse.bandwidth_result({"bench_aggregate": aggregate})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["gbps"], 4)
        aggregate["errors"] = 1
        result = analyse.bandwidth_result({"bench_aggregate": aggregate})
        self.assertEqual(result["status"], "invalid")
        self.assertIsNone(result["gbps"])

    def test_bandwidth_aggregate_parser_and_missing_party(self):
        path = self.directory / "core-1.bench.log"
        path.write_text("Bandwidth benchmark aggregate: status=complete sessions=1/1 acknowledged_bytes=1000000000 "
                        "attempts=10 successes=10 timeouts=0 errors=0 elapsed_s=2.000000\n")
        parsed = analyse.parse_core_log(str(path))
        self.assertEqual(analyse.bandwidth_result(parsed)["gbps"], 4)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyse.bw([str(path)], expected_parties=2), 1)

    def test_legacy_bandwidth_is_exploratory_without_goodput(self):
        result = analyse.bandwidth_result({"bench": [(1, 1, 10, [(2, 100, 10, 10, 5, 0, 0)])]})
        self.assertEqual(result["status"], "exploratory")
        self.assertIsNone(result["gbps"])

    def run_watcher(self, fail_party):
        binary = self.directory / "bin"
        binary.mkdir()
        kubectl = binary / "kubectl"
        kubectl.write_text('''kubectl() {
case " $* " in
  *" exec "*)
    case " $* " in
      *"http://kms-core-2-core-2:"*) [ "$WATCH_TEST_FAIL_PARTY" = "2" ] && return 1;;
    esac
    printf 'kms_total_cpus 52\\nkms_process_cpu_usage 1000\\nkms_network_tx_bytes_total 100\\nkms_network_rx_bytes_total 100\\n'
    ;;
  *" top "*) printf 'kms-core-1-core-1 enclave-network-tunnel 10m 100Mi\\n';;
esac
return 0
}
''')
        stop = self.directory / "stop"
        stop.touch()
        environment = dict(os.environ, BASH_ENV=str(kubectl),
                           NAMESPACE="test", PARTIES="1 2", INTERVAL="1",
                           RAW_DIR=str(self.directory / "raw"), READY_FILE=str(self.directory / "ready"),
                           STOP_FILE=str(stop), WATCH_TEST_FAIL_PARTY=fail_party)
        return subprocess.run(["bash", str(Path(__file__).with_name("manual-metrics-watch.sh"))],
                              env=environment, capture_output=True, text=True, timeout=10)

    def test_watcher_marks_ready_after_all_party_scrapes_and_exits_after_final_round(self):
        result = self.run_watcher("")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.directory / "ready").exists())
        for party in (1, 2):
            paths = list((self.directory / "raw" / f"p{party}").glob("*.prom"))
            self.assertEqual(len(paths), 1)
            self.assertGreater(float(paths[0].name[:-5]), 0)
        self.assertNotIn("VERDICT", result.stdout)

    def test_watcher_rejects_incomplete_final_round(self):
        result = self.run_watcher("2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.directory / "ready").exists())
        self.assertIn("final scrape round incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
