#!/usr/bin/env python3

import argparse
import csv
import glob
import logging
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


TFHE_RUN_4P_NAME = "tfhe-bench-run-4p"
TFHE_RUN_4P_MALICIOUS_NAME = "tfhe-bench-run-4p-malicious-bcast"
TFHE_RUN_5P_NAME = "tfhe-bench-run-5p"
TFHE_RUN_NAMES = [TFHE_RUN_4P_NAME, TFHE_RUN_4P_MALICIOUS_NAME, TFHE_RUN_5P_NAME]
BGV_RUN_NAME = "bgv-bench-run"

NUM_CTXTS = 10

def build_tfhe_operation_labels(include_prss_init: bool) -> List[str]:
    labels = []
    if include_prss_init:
        labels.extend([
            "PRSS_INIT_Z64",
            "PRSS_INIT_Z128",
        ])
    labels.extend([
        "DKG_PREPROC",
        "DKG",
        "CRS_GEN",
        "RESHARE",
    ])
    for mode in ["NOISE_FLOOD_SMALL", "BIT_DEC_SMALL"]:
        for tfhe_type in ["bool", "u4", "u8", "u16", "u32", "u64", "u128"]:
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
    NUM_CTXTS ciphertexts.  All other operations return 1.
    """
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
    complete_run_index: int,
    party_files: List[str],
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    spread_warn_threshold: float,
) -> List[List[object]]:
    rows: List[List[object]] = []
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
        rows.append(
            [
                complete_run_index,
                source_run_index + 1,
                op_idx + 1,
                operation_labels[op_idx],
                per_party_metrics[0][1].name,
                average(num_sessions_values),
                average(num_rounds_values),
                average(network_sent_values),
                average(network_received_values),
                average(time_active_values) / num_ctxts,
            ]
        )

    return rows


def write_csv(path: str, rows: List[List[object]]) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Parse session_stats_*.txt files from all parties, keep only complete TFHE/BGV runs, "
            "compute cross-party averages, and export TFHE/BGV CSV files."
        )
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing session_stats_*.txt files for all parties.",
    )
    parser.add_argument(
        "output_suffix",
        help="Suffix appended to output CSV names: TFHE_<NUM_PARTIES>_<suffix>.csv and BGV_<NUM_PARTIES>_<suffix>.csv.",
    )
    parser.add_argument(
        "--pattern",
        default="session_stats_*.txt",
        help="Glob pattern used inside input_dir to find party files (default: session_stats_*.txt).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for generated CSV files (default: current directory).",
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

    all_run_names = TFHE_RUN_NAMES + [BGV_RUN_NAME]
    all_complete_runs = {**tfhe_complete_runs_by_name, BGV_RUN_NAME: bgv_complete_runs}
    all_run_party_files = {**tfhe_party_files_by_name, BGV_RUN_NAME: bgv_party_files}

    for run_name in all_run_names:
        run_party_files = all_run_party_files[run_name]
        complete_runs = all_complete_runs[run_name]
        run_num_parties = len(run_party_files)

        rows: List[List[object]] = []
        for complete_idx, run_idx in enumerate(complete_runs, start=1):
            rows.extend(
                aggregate_run(
                    run_name=run_name,
                    source_run_index=run_idx,
                    complete_run_index=complete_idx,
                    party_files=run_party_files,
                    all_party_runs=all_party_runs,
                    spread_warn_threshold=args.spread_warning_threshold,
                )
            )

        output_path = os.path.join(
            args.output_dir, f"{run_name}_{run_num_parties}p_{args.output_suffix}.csv"
        )
        write_csv(output_path, rows)
        print(f"Complete {run_name} runs: {len(complete_runs)}")
        print(f"Wrote CSV: {output_path}")

    print(f"Parsed {num_parties} party files.")


if __name__ == "__main__":
    main()