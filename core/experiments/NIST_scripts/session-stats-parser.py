#!/usr/bin/env python3

import argparse
import csv
import glob
import logging
import os
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


TFHE_RUN_4P_NAME = "tfhe-bench-run-4p"
TFHE_RUN_4P_MALICIOUS_NAME = "tfhe-bench-run-4p-malicious-bcast"
TFHE_RUN_5P_NAME = "tfhe-bench-run-5p"
TFHE_RUN_NAMES = [TFHE_RUN_4P_NAME, TFHE_RUN_4P_MALICIOUS_NAME, TFHE_RUN_5P_NAME]
BGV_RUN_NAME = "bgv-bench-run"

NUM_CTXTS = 10

# TFHE message types and their bit widths. bool is reported with bit_width = 1.
TFHE_TYPES = ["bool", "u4", "u8", "u16", "u32", "u64", "u128"]
TFHE_TYPE_TO_BIT_WIDTH: Dict[str, int] = {
    "bool": 1,
    "u4": 4,
    "u8": 8,
    "u16": 16,
    "u32": 32,
    "u64": 64,
    "u128": 128,
}
# Bit widths kept in the aggregated TDecOne/TDecTwo CSVs. u128 is intentionally dropped.
TDEC_BIT_WIDTHS = [1, 4, 8, 16, 32, 64]

NOISE_FLOOD_MODE = "NOISE_FLOOD_SMALL"
BIT_DEC_MODE = "BIT_DEC_SMALL"


def build_tfhe_operation_labels(include_prss_init: bool) -> List[str]:
    labels: List[str] = []
    if include_prss_init:
        labels.extend([
            "PRSS_INIT_Z64",
            "PRSS_INIT_Z128",
        ])
    labels.extend([
        "DKG_PREPROC",
        "DKG",
        "CRS_GEN",
        # Reshare now emits two consecutive session-stats lines: preprocessing
        # (RESHARE-PREPROC in the source) followed by the online phase (RESHARE).
        "RESHARE_PREPROC",
        "RESHARE",
    ])
    for mode in [NOISE_FLOOD_MODE, BIT_DEC_MODE]:
        for tfhe_type in TFHE_TYPES:
            labels.append(f"{mode}_{tfhe_type}_PREPROC")
            labels.append(f"{mode}_{tfhe_type}_DDEC")
    return labels


TFHE_4P_OPERATION_LABELS = build_tfhe_operation_labels(include_prss_init=True)
TFHE_5P_OPERATION_LABELS = build_tfhe_operation_labels(include_prss_init=False)


EXPECTED_LINES_PER_RUN = {
    TFHE_RUN_4P_NAME: len(TFHE_4P_OPERATION_LABELS),
    TFHE_RUN_4P_MALICIOUS_NAME: len(TFHE_4P_OPERATION_LABELS),
    TFHE_RUN_5P_NAME: len(TFHE_5P_OPERATION_LABELS),
    BGV_RUN_NAME: 10,
}


OPERATION_LABELS = {
    TFHE_RUN_4P_NAME: TFHE_4P_OPERATION_LABELS,
    TFHE_RUN_4P_MALICIOUS_NAME: TFHE_4P_OPERATION_LABELS,
    TFHE_RUN_5P_NAME: TFHE_5P_OPERATION_LABELS,
    BGV_RUN_NAME: [
        "PRSS_INIT_LEVEL_ONE",
        "PRSS_INIT_LEVEL_KSW",
        "DKG_PREPROC",
        "DKG",
        "DDEC_PARALLEL_1",
        "DDEC_PARALLEL_2",
        "DDEC_PARALLEL_4",
        "DDEC_PARALLEL_8",
        "DDEC_PARALLEL_16",
        "DDEC_PARALLEL_32",
    ],
}


def num_ctxts_for_label(label: str) -> int:
    """Return the number of ciphertexts processed by an operation.

    Decrypt-related operations (PREPROC, DDEC, DDEC_PARALLEL) each process
    NUM_CTXTS ciphertexts.  RESHARE_PREPROC and RESHARE are reshare-only and
    are not per-ciphertext.  All other operations return 1.
    """
    if label.startswith("RESHARE"):
        return 1
    if "PREPROC" in label and "DKG" not in label:
        return NUM_CTXTS
    if "DDEC" in label:
        return NUM_CTXTS
    return 1


@dataclass
class MetricLine:
    name: str
    role: int
    num_sessions: int
    num_rounds: int
    network_sent: int
    network_received: int
    time_active: int


@dataclass
class AggregatedOperation:
    """Cross-party averaged metrics for one operation in one run.

    ``avg_time_active_ms`` is already divided by ``num_ctxts_for_label(label)``
    so it is per-ciphertext for DDEC/PREPROC labels and per-operation for
    everything else.  ``avg_network_sent_B`` and ``avg_network_received_B`` are
    batch totals (the existing parser does not divide them by num_ctxts).
    """

    label: str
    reported_name: str
    avg_num_sessions: float
    avg_num_rounds: float
    avg_network_sent_B: float
    avg_network_received_B: float
    avg_time_active_ms: float


def parse_metric_line(raw_line: str) -> MetricLine:
    fields: Dict[str, str] = {}
    for chunk in raw_line.strip().split(","):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        fields[key.strip()] = value.strip()

    try:
        return MetricLine(
            name=fields["name"],
            role=int(fields["role"]),
            num_sessions=int(fields["num_sessions"]),
            num_rounds=int(fields["num_rounds"]),
            network_sent=int(fields["network_sent(B)"]),
            network_received=int(fields["network_received(B)"]),
            time_active=int(fields["time_active(ms)"]),
        )
    except KeyError as exc:
        raise ValueError(f"Missing expected key {exc} in line: {raw_line.strip()}") from exc


def split_run_marker(marker: str) -> Tuple[str, str]:
    for run_name in TFHE_RUN_NAMES + [BGV_RUN_NAME]:
        if marker == run_name:
            return run_name, ""
        run_prefix = f"{run_name} "
        if marker.startswith(run_prefix):
            return run_name, marker[len(run_prefix) :].strip()
    return "", ""


def parse_session_stats_file(path: str) -> Tuple[Dict[str, List[List[MetricLine]]], Dict[str, List[str]]]:
    runs: Dict[str, List[List[MetricLine]]] = {run_name: [] for run_name in TFHE_RUN_NAMES}
    runs[BGV_RUN_NAME] = []
    run_ids: Dict[str, List[str]] = {run_name: [] for run_name in TFHE_RUN_NAMES}
    run_ids[BGV_RUN_NAME] = []

    current_run_name = ""
    current_run_id = ""
    current_run_lines: List[MetricLine] = []

    with open(path, "r", encoding="utf-8") as file_handle:
        for raw_line in file_handle:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("NEW_RUN:"):
                if current_run_name in runs:
                    runs[current_run_name].append(current_run_lines)
                    run_ids[current_run_name].append(current_run_id)
                current_run_lines = []
                run_marker = line.split(":", 1)[1].strip()
                current_run_name, current_run_id = split_run_marker(run_marker)
                continue

            if line.startswith("name="):
                if current_run_name in runs:
                    current_run_lines.append(parse_metric_line(line))
                continue

    if current_run_name in runs:
        runs[current_run_name].append(current_run_lines)
        run_ids[current_run_name].append(current_run_id)

    return runs, run_ids


def average(values: List[int]) -> float:
    return float(sum(values)) / float(len(values))


def relative_spread(values: List[int]) -> float:
    if not values:
        return 0.0
    mean_value = average(values)
    denominator = abs(mean_value)
    if denominator < 1.0:
        denominator = 1.0
    return float(max(values) - min(values)) / denominator


def warn_if_large_spread(
    run_name: str,
    run_index: int,
    operation_index: int,
    metric_name: str,
    values: List[int],
    threshold: float,
) -> None:
    spread = relative_spread(values)
    if spread > threshold:
        logger.warning(
            "Large spread for %s across parties in run=%s, run_index=%s, "
            "operation_index=%s: min=%s, max=%s, mean=%.3f, rel_spread=%.3f",
            metric_name, run_name, run_index, operation_index,
            min(values), max(values), average(values), spread,
        )


def collect_complete_run_indexes(
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    all_party_run_ids: Dict[str, Dict[str, List[str]]],
    run_name: str,
    party_files: List[str],
) -> List[int]:
    if not party_files:
        logger.warning("Skipping run=%s because no party files were selected for this run", run_name)
        return []

    complete_indexes: List[int] = []
    expected_len = EXPECTED_LINES_PER_RUN[run_name]
    max_runs = max(len(all_party_runs[path][run_name]) for path in party_files)

    for run_idx in range(max_runs):
        run_is_complete_for_all = True
        for party_file in party_files:
            runs_for_party = all_party_runs[party_file][run_name]
            run_ids_for_party = all_party_run_ids[party_file][run_name]
            if run_idx >= len(runs_for_party):
                run_is_complete_for_all = False
                logger.warning(
                    "Skipping run=%s, run_index=%s because party file %s "
                    "does not contain this run index",
                    run_name, run_idx + 1, party_file,
                )
                continue

            if run_idx >= len(run_ids_for_party):
                run_is_complete_for_all = False
                logger.warning(
                    "Skipping run=%s, run_index=%s because party file %s "
                    "does not contain run ID metadata for this run index",
                    run_name, run_idx + 1, party_file,
                )
                continue

            line_count = len(runs_for_party[run_idx])
            if line_count != expected_len:
                run_is_complete_for_all = False
                logger.warning(
                    "Skipping run=%s, run_index=%s because party file %s has "
                    "%s metric lines but expected %s",
                    run_name, run_idx + 1, party_file, line_count, expected_len,
                )

        if run_is_complete_for_all:
            run_ids_at_index = [all_party_run_ids[party_file][run_name][run_idx] for party_file in party_files]
            non_empty_run_ids = [run_id for run_id in run_ids_at_index if run_id]
            if non_empty_run_ids and len(set(non_empty_run_ids)) > 1:
                run_is_complete_for_all = False
                logger.warning(
                    "Skipping run=%s, run_index=%s because run IDs differ across parties: %s",
                    run_name, run_idx + 1, run_ids_at_index,
                )

        if run_is_complete_for_all:
            complete_indexes.append(run_idx)

    return complete_indexes


def expected_party_count_for_run(run_name: str) -> int:
    if "-4p" in run_name:
        return 4
    if "-5p" in run_name:
        return 5
    if run_name == BGV_RUN_NAME:
        return 4
    return 0


def honest_party_count_for_run(run_name: str) -> int:
    expected_party_count = expected_party_count_for_run(run_name)
    if "malicious" in run_name and expected_party_count > 0:
        return expected_party_count - 1
    return expected_party_count


def is_malicious_run(run_name: str) -> int:
    return 1 if "malicious" in run_name else 0


def select_party_files_for_run(
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    run_name: str,
    party_files: List[str],
) -> List[str]:
    selected_party_files = [
        party_file for party_file in party_files if len(all_party_runs[party_file][run_name]) > 0
    ]

    expected_party_count = expected_party_count_for_run(run_name)
    target_party_count = honest_party_count_for_run(run_name)

    if "malicious" in run_name and target_party_count > 0 and len(selected_party_files) > target_party_count:
        expected_len = EXPECTED_LINES_PER_RUN[run_name]
        # Keep parties with the most complete runs first; this drops malformed/incomplete malicious-party logs.
        ranked_files = sorted(
            selected_party_files,
            key=lambda path: sum(1 for run in all_party_runs[path][run_name] if len(run) == expected_len),
            reverse=True,
        )
        kept_files = ranked_files[:target_party_count]
        dropped_files = ranked_files[target_party_count:]
        logger.warning(
            "run=%s identified as malicious benchmark; excluding potential malicious/invalid party files from averaging: %s",
            run_name, dropped_files,
        )
        selected_party_files = kept_files

    if target_party_count and len(selected_party_files) != target_party_count:
        logger.warning(
            "run=%s expected %s participating party files based on run name but found %s: %s",
            run_name, target_party_count, len(selected_party_files), selected_party_files,
        )

    return selected_party_files


def aggregate_run(
    run_name: str,
    source_run_index: int,
    party_files: List[str],
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    spread_warn_threshold: float,
) -> List[AggregatedOperation]:
    """Aggregate one source-run-index across parties into a list of
    ``AggregatedOperation``s ordered by the run's operation labels."""
    aggregated: List[AggregatedOperation] = []
    operation_labels = OPERATION_LABELS[run_name]
    expected_len = EXPECTED_LINES_PER_RUN[run_name]

    for op_idx in range(expected_len):
        per_party_metrics: List[Tuple[str, MetricLine]] = []
        for party_file in party_files:
            metric_line = all_party_runs[party_file][run_name][source_run_index][op_idx]
            per_party_metrics.append((party_file, metric_line))

        names = {metric_line.name for _, metric_line in per_party_metrics}
        if len(names) > 1:
            logger.warning(
                "Name mismatch across parties in run=%s, run_index=%s, "
                "operation_index=%s: names=%s",
                run_name, source_run_index + 1, op_idx + 1, sorted(names),
            )

        num_sessions_values = [metric_line.num_sessions for _, metric_line in per_party_metrics]
        if len(set(num_sessions_values)) > 1:
            logger.error(
                "num_sessions mismatch across parties in run=%s, run_index=%s, "
                "operation_index=%s: values=%s",
                run_name, source_run_index + 1, op_idx + 1, num_sessions_values,
            )

        num_rounds_values = [metric_line.num_rounds for _, metric_line in per_party_metrics]
        if len(set(num_rounds_values)) > 1:
            logger.error(
                "num_rounds mismatch across parties in run=%s, run_index=%s, "
                "operation_index=%s: values=%s",
                run_name, source_run_index + 1, op_idx + 1, num_rounds_values,
            )

        network_sent_values = [metric_line.network_sent for _, metric_line in per_party_metrics]
        network_received_values = [metric_line.network_received for _, metric_line in per_party_metrics]
        time_active_values = [metric_line.time_active for _, metric_line in per_party_metrics]

        for party_file, metric_line in per_party_metrics:
            if metric_line.network_sent != metric_line.network_received:
                logger.warning(
                    "network_sent != network_received in %s, run=%s, run_index=%s, "
                    "operation_index=%s: sent=%s, received=%s",
                    party_file, run_name, source_run_index + 1, op_idx + 1,
                    metric_line.network_sent, metric_line.network_received,
                )

        warn_if_large_spread(
            run_name=run_name,
            run_index=source_run_index + 1,
            operation_index=op_idx + 1,
            metric_name="network_sent(B)",
            values=network_sent_values,
            threshold=spread_warn_threshold,
        )
        warn_if_large_spread(
            run_name=run_name,
            run_index=source_run_index + 1,
            operation_index=op_idx + 1,
            metric_name="network_received(B)",
            values=network_received_values,
            threshold=spread_warn_threshold,
        )
        warn_if_large_spread(
            run_name=run_name,
            run_index=source_run_index + 1,
            operation_index=op_idx + 1,
            metric_name="time_active(ms)",
            values=time_active_values,
            threshold=spread_warn_threshold,
        )

        num_ctxts = num_ctxts_for_label(operation_labels[op_idx])
        aggregated.append(
            AggregatedOperation(
                label=operation_labels[op_idx],
                reported_name=per_party_metrics[0][1].name,
                avg_num_sessions=average(num_sessions_values),
                avg_num_rounds=average(num_rounds_values),
                avg_network_sent_B=average(network_sent_values),
                avg_network_received_B=average(network_received_values),
                avg_time_active_ms=average(time_active_values) / num_ctxts,
            )
        )

    return aggregated


def find_operation(
    aggregated: List[AggregatedOperation],
    label: str,
) -> Optional[AggregatedOperation]:
    for op in aggregated:
        if op.label == label:
            return op
    return None


# ---------------------------------------------------------------------------
# Legacy per-run CSV emission
# ---------------------------------------------------------------------------
#
# The functions below were used by the previous entry point to write one CSV
# per run-name (e.g. ``tfhe-bench-run-4p_4p_TestParams.csv``).  The current
# entry point produces the new per-iteration aggregated CSVs and does NOT call
# these helpers, but they are kept here as building blocks in case a caller
# wants the per-run shape back.


def aggregated_to_per_run_rows(
    aggregated: List[AggregatedOperation],
    complete_run_index: int,
    source_run_index: int,
) -> List[List[object]]:
    """Build the rows of the legacy per-run CSV from one run's aggregated metrics."""
    return [
        [
            complete_run_index,
            source_run_index + 1,
            op_idx + 1,
            op.label,
            op.reported_name,
            op.avg_num_sessions,
            op.avg_num_rounds,
            op.avg_network_sent_B,
            op.avg_network_received_B,
            op.avg_time_active_ms,
        ]
        for op_idx, op in enumerate(aggregated)
    ]


def write_per_run_csv(path: str, rows: List[List[object]]) -> None:
    """Legacy per-run CSV writer (not called by ``main``)."""
    with open(path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "run_index",
                "source_run_index",
                "operation_index",
                "operation_label",
                "reported_name",
                "avg_num_sessions",
                "avg_num_rounds",
                "avg_network_sent_B",
                "avg_network_received_B",
                "avg_time_active_ms",
            ]
        )
        for row in rows:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Aggregated per-iteration CSV emission
# ---------------------------------------------------------------------------


CRS_HEADERS = [
    "malicious",
    "num_parties",
    "avg_latency_ms",
    "rounds",
    "avg_bytes_sent_per_party",
    "avg_bytes_received_per_party",
    "max_memory_kBytes",
]


# Shared headers for KeyGen and Reshare CSVs (same shape, different sources).
TWO_PHASE_HEADERS = [
    "malicious",
    "num_parties",
    "offline_avg_latency_ms",
    "offline_rounds",
    "offline_avg_bytes_sent_per_party",
    "offline_avg_bytes_received_per_party",
    "offline_max_memory_kBytes",
    "offline_avg_mem_kBytes",
    "online_avg_latency_ms",
    "online_rounds",
    "online_avg_bytes_sent_per_party",
    "online_avg_bytes_received_per_party",
    "online_max_memory_kBytes",
    "online_avg_mem_kBytes",
]


# Shared headers for the two threshold-decryption CSVs.
TDEC_HEADERS = [
    "malicious",
    "num_parties",
    "num_ctxt",
    "offline_avg_latency_ms",
    "offline_throughput_per_sec",
    "online_avg_latency_ms",
    "online_throughput_per_sec",
    "offline_rounds",
    "online_rounds",
    "offline_avg_bytes_sent_per_party",
    "offline_avg_bytes_received_per_party",
    "online_avg_bytes_sent_per_party",
    "online_avg_bytes_received_per_party",
    "offline_max_memory_kBytes",
    "online_max_memory_kBytes",
]


# BGV decryption is single-phase (one ``DDEC_PARALLEL_N`` line per parallelism
# factor) so it gets a flatter CSV than the TFHE TDec ones.
BGV_TDEC_HEADERS = [
    "malicious",
    "num_parties",
    "num_ctxt",
    "avg_latency_ms",
    "throughput_per_sec",
    "rounds",
    "avg_bytes_sent_per_party",
    "avg_bytes_received_per_party",
    "max_memory_kBytes",
    "avg_mem_kBytes",
]


# Parallelism factors of the BGV ``DDEC_PARALLEL_N`` benchmark lines, one row
# per factor in the BGV TDec CSV.
BGV_DDEC_PARALLEL_FACTORS = [1, 2, 4, 8, 16, 32]


def _has_offline_phase(preproc: AggregatedOperation) -> bool:
    """An offline phase exists for a row iff its PREPROC line did real work,
    detected here by ``num_rounds != 0``."""
    return preproc.avg_num_rounds != 0


def _throughput_bits_per_sec(bit_width: int, per_ctxt_latency_ms: float) -> float:
    """Throughput in bits/sec given per-ciphertext latency in ms and message bit width.

    Per-ciphertext latency is what ``aggregate_run`` stores for DDEC/PREPROC
    rows; ``bit_width / per_ctxt_seconds`` is equivalent to
    ``bit_width * NUM_CTXTS / batch_seconds``.
    """
    if per_ctxt_latency_ms <= 0:
        return 0.0
    return bit_width * 1000.0 / per_ctxt_latency_ms


def _two_phase_row(
    run_name: str,
    preproc: AggregatedOperation,
    online: AggregatedOperation,
) -> List[object]:
    """Row for the KeyGen/Reshare CSVs.

    Memory cells are always ``-1`` (not measured here).  Offline cells become
    ``-1`` when the preproc line has ``num_rounds == 0``.
    """
    offline_present = _has_offline_phase(preproc)
    return [
        is_malicious_run(run_name),
        num_parties_for_run(run_name),
        preproc.avg_time_active_ms if offline_present else -1,
        preproc.avg_num_rounds if offline_present else -1,
        preproc.avg_network_sent_B if offline_present else -1,
        preproc.avg_network_received_B if offline_present else -1,
        -1,  # offline_max_memory_kBytes
        -1,  # offline_avg_mem_kBytes
        online.avg_time_active_ms,
        online.avg_num_rounds,
        online.avg_network_sent_B,
        online.avg_network_received_B,
        -1,  # online_max_memory_kBytes
        -1,  # online_avg_mem_kBytes
    ]


def _tdec_one_row(
    run_name: str,
    bit_width: int,
    preproc: AggregatedOperation,
    ddec: AggregatedOperation,
) -> List[object]:
    """Row for ``TFHE_TDecOne_*`` (NOISE_FLOOD).

    Offline is the PREPROC line (``-1`` when its ``num_rounds`` is 0); online
    is the sum of PREPROC + DDEC (latency, rounds, bytes summed; throughput
    recomputed from the summed per-ctxt latency).
    """
    offline_present = _has_offline_phase(preproc)
    online_latency_ms = preproc.avg_time_active_ms + ddec.avg_time_active_ms
    online_rounds = preproc.avg_num_rounds + ddec.avg_num_rounds
    online_bytes_sent = preproc.avg_network_sent_B + ddec.avg_network_sent_B
    online_bytes_received = preproc.avg_network_received_B + ddec.avg_network_received_B
    return [
        is_malicious_run(run_name),
        num_parties_for_run(run_name),
        bit_width,
        preproc.avg_time_active_ms if offline_present else -1,
        _throughput_bits_per_sec(bit_width, preproc.avg_time_active_ms) if offline_present else -1,
        online_latency_ms,
        _throughput_bits_per_sec(bit_width, online_latency_ms),
        preproc.avg_num_rounds if offline_present else -1,
        online_rounds,
        preproc.avg_network_sent_B if offline_present else -1,
        preproc.avg_network_received_B if offline_present else -1,
        online_bytes_sent,
        online_bytes_received,
        -1,  # offline_max_memory_kBytes
        -1,  # online_max_memory_kBytes
    ]


def _tdec_two_row(
    run_name: str,
    bit_width: int,
    preproc: AggregatedOperation,
    ddec: AggregatedOperation,
) -> List[object]:
    """Row for ``TFHE_TDecTwo_*`` (BIT_DEC).

    Offline is the PREPROC line (``-1`` when ``num_rounds`` is 0); online is
    the DDEC line.
    """
    offline_present = _has_offline_phase(preproc)
    return [
        is_malicious_run(run_name),
        num_parties_for_run(run_name),
        bit_width,
        preproc.avg_time_active_ms if offline_present else -1,
        _throughput_bits_per_sec(bit_width, preproc.avg_time_active_ms) if offline_present else -1,
        ddec.avg_time_active_ms,
        _throughput_bits_per_sec(bit_width, ddec.avg_time_active_ms),
        preproc.avg_num_rounds if offline_present else -1,
        ddec.avg_num_rounds,
        preproc.avg_network_sent_B if offline_present else -1,
        preproc.avg_network_received_B if offline_present else -1,
        ddec.avg_network_sent_B,
        ddec.avg_network_received_B,
        -1,
        -1,
    ]


def num_parties_for_run(run_name: str) -> int:
    return expected_party_count_for_run(run_name)


def _write_csv(path: str, headers: List[str], rows: List[List[object]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)
        writer.writerows(rows)


def write_crs_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    rows: List[List[object]] = []
    for run_name in TFHE_RUN_NAMES:
        aggregated = iteration_aggregates.get(run_name)
        if aggregated is None:
            continue
        crs = find_operation(aggregated, "CRS_GEN")
        if crs is None:
            # Should not happen; aggregate_run always returns one entry per label.
            continue
        rows.append([
            is_malicious_run(run_name),
            num_parties_for_run(run_name),
            crs.avg_time_active_ms,
            crs.avg_num_rounds,
            crs.avg_network_sent_B,
            crs.avg_network_received_B,
            -1,  # max_memory_kBytes — not measured here
        ])
    _write_csv(path, CRS_HEADERS, rows)


def _write_two_phase_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
    preproc_label: str,
    online_label: str,
) -> None:
    rows: List[List[object]] = []
    for run_name in TFHE_RUN_NAMES:
        aggregated = iteration_aggregates.get(run_name)
        if aggregated is None:
            continue
        preproc = find_operation(aggregated, preproc_label)
        online = find_operation(aggregated, online_label)
        if preproc is None or online is None:
            continue
        rows.append(_two_phase_row(run_name, preproc, online))
    _write_csv(path, TWO_PHASE_HEADERS, rows)


def write_keygen_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    _write_two_phase_csv(path, iteration_aggregates, "DKG_PREPROC", "DKG")


def write_reshare_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    _write_two_phase_csv(path, iteration_aggregates, "RESHARE_PREPROC", "RESHARE")


def _write_tdec_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
    mode: str,
    row_builder: Callable[[str, int, AggregatedOperation, AggregatedOperation], List[object]],
) -> None:
    rows: List[List[object]] = []
    for run_name in TFHE_RUN_NAMES:
        aggregated = iteration_aggregates.get(run_name)
        if aggregated is None:
            continue
        for tfhe_type in TFHE_TYPES:
            bit_width = TFHE_TYPE_TO_BIT_WIDTH[tfhe_type]
            if bit_width not in TDEC_BIT_WIDTHS:
                continue
            preproc = find_operation(aggregated, f"{mode}_{tfhe_type}_PREPROC")
            ddec = find_operation(aggregated, f"{mode}_{tfhe_type}_DDEC")
            if preproc is None or ddec is None:
                continue
            rows.append(row_builder(run_name, bit_width, preproc, ddec))
    _write_csv(path, TDEC_HEADERS, rows)


def write_tdec_one_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    _write_tdec_csv(path, iteration_aggregates, NOISE_FLOOD_MODE, _tdec_one_row)


def write_tdec_two_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    _write_tdec_csv(path, iteration_aggregates, BIT_DEC_MODE, _tdec_two_row)


def write_bgv_keygen_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    """BGV key generation CSV — same shape as ``TFHE_KeyGen_*``.

    Offline = ``DKG_PREPROC``, online = ``DKG``.  The ``num_rounds == 0 → -1``
    rule is reused mechanically; in practice BGV ``DKG_PREPROC`` always has
    real rounds so offline is never blanked out here.
    """
    rows: List[List[object]] = []
    aggregated = iteration_aggregates.get(BGV_RUN_NAME)
    if aggregated is not None:
        preproc = find_operation(aggregated, "DKG_PREPROC")
        online = find_operation(aggregated, "DKG")
        if preproc is not None and online is not None:
            rows.append(_two_phase_row(BGV_RUN_NAME, preproc, online))
    _write_csv(path, TWO_PHASE_HEADERS, rows)


def write_bgv_tdec_csv(
    path: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
) -> None:
    """BGV threshold-decryption CSV.

    One row per parallelism factor ``N`` in ``BGV_DDEC_PARALLEL_FACTORS``,
    sourced from the corresponding ``DDEC_PARALLEL_N`` line.  Throughput is
    decryptions per second: ``N × 1000 / per_call_latency_ms`` (``aggregate_run``
    already divides ``time_active`` by ``NUM_CTXTS``, so the stored
    ``avg_time_active_ms`` is the per-call latency of one ``DDEC_PARALLEL_N``
    invocation that decrypts ``N`` ciphertexts in parallel).
    """
    rows: List[List[object]] = []
    aggregated = iteration_aggregates.get(BGV_RUN_NAME)
    if aggregated is not None:
        for parallel_n in BGV_DDEC_PARALLEL_FACTORS:
            ddec = find_operation(aggregated, f"DDEC_PARALLEL_{parallel_n}")
            if ddec is None:
                continue
            throughput = (
                parallel_n * 1000.0 / ddec.avg_time_active_ms
                if ddec.avg_time_active_ms > 0
                else 0.0
            )
            rows.append([
                is_malicious_run(BGV_RUN_NAME),  # always 0 — no malicious BGV run
                num_parties_for_run(BGV_RUN_NAME),
                parallel_n,
                ddec.avg_time_active_ms,
                throughput,
                ddec.avg_num_rounds,
                ddec.avg_network_sent_B,
                ddec.avg_network_received_B,
                -1,  # max_memory_kBytes — not measured here
                -1,  # avg_mem_kBytes — not measured here
            ])
    _write_csv(path, BGV_TDEC_HEADERS, rows)


def write_iteration_csvs(
    iteration_dir: str,
    iteration_aggregates: Dict[str, List[AggregatedOperation]],
    suffix: str,
) -> None:
    """Write the five aggregated CSVs for one iteration into ``iteration_dir``."""
    os.makedirs(iteration_dir, exist_ok=True)
    write_crs_csv(
        os.path.join(iteration_dir, f"CRS_{suffix}.csv"),
        iteration_aggregates,
    )
    write_keygen_csv(
        os.path.join(iteration_dir, f"TFHE_KeyGen_{suffix}.csv"),
        iteration_aggregates,
    )
    write_reshare_csv(
        os.path.join(iteration_dir, f"TFHE_Reshare_{suffix}.csv"),
        iteration_aggregates,
    )
    write_tdec_one_csv(
        os.path.join(iteration_dir, f"TFHE_TDecOne_{suffix}.csv"),
        iteration_aggregates,
    )
    write_tdec_two_csv(
        os.path.join(iteration_dir, f"TFHE_TDecTwo_{suffix}.csv"),
        iteration_aggregates,
    )
    write_bgv_keygen_csv(
        os.path.join(iteration_dir, f"BGV_KeyGen_{suffix}.csv"),
        iteration_aggregates,
    )
    write_bgv_tdec_csv(
        os.path.join(iteration_dir, f"BGV_TDec_{suffix}.csv"),
        iteration_aggregates,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Parse session_stats_*.txt files from all parties, keep only "
            "complete TFHE/BGV runs, compute cross-party averages, and emit "
            "per-iteration aggregated CSVs (CRS, TFHE_KeyGen, TFHE_Reshare, "
            "TFHE_TDecOne, TFHE_TDecTwo, BGV_KeyGen, BGV_TDec) under "
            "<output-dir>/iteration_<N>/."
        )
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing session_stats_*.txt files for all parties.",
    )
    parser.add_argument(
        "output_suffix",
        help=(
            "Suffix appended to output CSV names: CRS_<suffix>.csv, "
            "TFHE_KeyGen_<suffix>.csv, TFHE_Reshare_<suffix>.csv, "
            "TFHE_TDecOne_<suffix>.csv, TFHE_TDecTwo_<suffix>.csv, "
            "BGV_KeyGen_<suffix>.csv, BGV_TDec_<suffix>.csv."
        ),
    )
    parser.add_argument(
        "--pattern",
        default="session_stats_*.txt",
        help="Glob pattern used inside input_dir to find party files (default: session_stats_*.txt).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help=(
            "Output root directory. Each iteration's CSVs are written to "
            "<output-dir>/iteration_<N>/. Default: current directory."
        ),
    )
    parser.add_argument(
        "--spread-warning-threshold",
        type=float,
        default=0.20,
        help=(
            "Relative spread threshold for cross-party warning. "
            "Spread is (max-min)/max(abs(mean),1). Default: 0.20"
        ),
    )
    parser.add_argument(
        "--warn",
        action="store_true",
        default=False,
        help="Enable warning messages on stderr (silenced by default).",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.WARNING if args.warn else logging.ERROR,
    )

    party_files = sorted(glob.glob(os.path.join(args.input_dir, args.pattern)))
    if not party_files:
        logger.error("No files found matching %s in directory %s", args.pattern, args.input_dir)
        sys.exit(1)

    num_parties = len(party_files)
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]] = {}
    all_party_run_ids: Dict[str, Dict[str, List[str]]] = {}
    for party_file in party_files:
        runs, run_ids = parse_session_stats_file(party_file)
        all_party_runs[party_file] = runs
        all_party_run_ids[party_file] = run_ids

    tfhe_complete_runs_by_name: Dict[str, List[int]] = {}
    tfhe_party_files_by_name: Dict[str, List[str]] = {}
    for tfhe_run_name in TFHE_RUN_NAMES:
        tfhe_party_files = select_party_files_for_run(
            all_party_runs=all_party_runs,
            run_name=tfhe_run_name,
            party_files=party_files,
        )
        tfhe_party_files_by_name[tfhe_run_name] = tfhe_party_files
        tfhe_complete_runs_by_name[tfhe_run_name] = collect_complete_run_indexes(
            all_party_runs=all_party_runs,
            all_party_run_ids=all_party_run_ids,
            run_name=tfhe_run_name,
            party_files=tfhe_party_files,
        )

    bgv_party_files = select_party_files_for_run(
        all_party_runs=all_party_runs,
        run_name=BGV_RUN_NAME,
        party_files=party_files,
    )
    bgv_complete_runs = collect_complete_run_indexes(
        all_party_runs=all_party_runs,
        all_party_run_ids=all_party_run_ids,
        run_name=BGV_RUN_NAME,
        party_files=bgv_party_files,
    )

    os.makedirs(args.output_dir, exist_ok=True)

    # Iteration N pairs the N-th complete run of each TFHE run-name with the
    # N-th complete BGV run. If counts differ, the iteration count is the max
    # and rows for missing runs are simply omitted from that iteration's CSVs.
    max_iterations = max(
        [len(indexes) for indexes in tfhe_complete_runs_by_name.values()]
        + [len(bgv_complete_runs)],
        default=0,
    )

    if max_iterations == 0:
        logger.error("No complete TFHE/BGV iterations found in %s", args.input_dir)
        sys.exit(1)

    for iteration_idx in range(max_iterations):
        iteration_aggregates: Dict[str, List[AggregatedOperation]] = {}
        for run_name in TFHE_RUN_NAMES:
            complete_runs = tfhe_complete_runs_by_name[run_name]
            if iteration_idx >= len(complete_runs):
                logger.warning(
                    "Iteration %s: run %s has no complete run at this ordinal; "
                    "rows for this run will be omitted from the iteration CSVs.",
                    iteration_idx + 1, run_name,
                )
                continue
            source_run_idx = complete_runs[iteration_idx]
            party_files_for_run = tfhe_party_files_by_name[run_name]
            iteration_aggregates[run_name] = aggregate_run(
                run_name=run_name,
                source_run_index=source_run_idx,
                party_files=party_files_for_run,
                all_party_runs=all_party_runs,
                spread_warn_threshold=args.spread_warning_threshold,
            )

        if iteration_idx < len(bgv_complete_runs):
            source_run_idx = bgv_complete_runs[iteration_idx]
            iteration_aggregates[BGV_RUN_NAME] = aggregate_run(
                run_name=BGV_RUN_NAME,
                source_run_index=source_run_idx,
                party_files=bgv_party_files,
                all_party_runs=all_party_runs,
                spread_warn_threshold=args.spread_warning_threshold,
            )
        else:
            logger.warning(
                "Iteration %s: BGV has no complete run at this ordinal; "
                "BGV_KeyGen and BGV_TDec CSVs will be empty for this iteration.",
                iteration_idx + 1,
            )

        iteration_dir = os.path.join(
            args.output_dir, f"iteration_{iteration_idx + 1}"
        )
        write_iteration_csvs(iteration_dir, iteration_aggregates, args.output_suffix)
        print(f"Wrote iteration_{iteration_idx + 1} CSVs to {iteration_dir}")

    print(f"Parsed {num_parties} party files; {max_iterations} iterations produced.")


if __name__ == "__main__":
    main()
