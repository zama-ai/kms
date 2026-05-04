#!/usr/bin/env python3

import argparse
import csv
import glob
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple


TFHE_RUN_4P_NAME = "tfhe-bench-run-4p"
TFHE_RUN_5P_NAME = "tfhe-bench-run-5p"
TFHE_RUN_NAMES = [TFHE_RUN_4P_NAME, TFHE_RUN_5P_NAME]
BGV_RUN_NAME = "bgv-bench-run"

EXPECTED_LINES_PER_RUN = {
    TFHE_RUN_4P_NAME: 28,
    TFHE_RUN_5P_NAME: 28,
    BGV_RUN_NAME: 7,
}


def build_tfhe_operation_labels() -> List[str]:
    labels = [
        "PRSS_INIT_Z64",
        "PRSS_INIT_Z128",
        "DKG_PREPROC",
        "DKG",
    ]
    for mode in ["NOISE_FLOOD_SMALL", "BIT_DEC_SMALL"]:
        for tfhe_type in ["bool", "u4", "u8", "u16", "u32", "u64"]:
            labels.append(f"{mode}_{tfhe_type}_PREPROC")
            labels.append(f"{mode}_{tfhe_type}_DDEC")
    return labels


OPERATION_LABELS = {
    TFHE_RUN_4P_NAME: build_tfhe_operation_labels(),
    TFHE_RUN_5P_NAME: build_tfhe_operation_labels(),
    BGV_RUN_NAME: [
        "PRSS_INIT_LEVEL_ONE",
        "PRSS_INIT_LEVEL_KSW",
        "DKG_PREPROC",
        "DKG",
        "DDEC_PARALLEL_1",
        "DDEC_PARALLEL_2",
        "DDEC_PARALLEL_4",
    ],
}


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
        print(
            (
                "WARNING: Large spread for {metric} across parties in run={run}, run_index={run_idx}, "
                "operation_index={op_idx}: min={min_v}, max={max_v}, mean={mean_v:.3f}, rel_spread={spread:.3f}"
            ).format(
                metric=metric_name,
                run=run_name,
                run_idx=run_index,
                op_idx=operation_index,
                min_v=min(values),
                max_v=max(values),
                mean_v=average(values),
                spread=spread,
            ),
            file=sys.stderr,
        )


def collect_complete_run_indexes(
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    all_party_run_ids: Dict[str, Dict[str, List[str]]],
    run_name: str,
    party_files: List[str],
) -> List[int]:
    if not party_files:
        print(
            f"WARNING: Skipping run={run_name} because no party files were selected for this run",
            file=sys.stderr,
        )
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
                print(
                    (
                        "WARNING: Skipping run={run}, run_index={run_idx} because party file {path} "
                        "does not contain this run index"
                    ).format(run=run_name, run_idx=run_idx + 1, path=party_file),
                    file=sys.stderr,
                )
                continue

            if run_idx >= len(run_ids_for_party):
                run_is_complete_for_all = False
                print(
                    (
                        "WARNING: Skipping run={run}, run_index={run_idx} because party file {path} "
                        "does not contain run ID metadata for this run index"
                    ).format(run=run_name, run_idx=run_idx + 1, path=party_file),
                    file=sys.stderr,
                )
                continue

            line_count = len(runs_for_party[run_idx])
            if line_count != expected_len:
                run_is_complete_for_all = False
                print(
                    (
                        "WARNING: Skipping run={run}, run_index={run_idx} because party file {path} has "
                        "{found} metric lines but expected {expected}"
                    ).format(
                        run=run_name,
                        run_idx=run_idx + 1,
                        path=party_file,
                        found=line_count,
                        expected=expected_len,
                    ),
                    file=sys.stderr,
                )

        if run_is_complete_for_all:
            run_ids_at_index = [all_party_run_ids[party_file][run_name][run_idx] for party_file in party_files]
            non_empty_run_ids = [run_id for run_id in run_ids_at_index if run_id]
            if non_empty_run_ids and len(set(non_empty_run_ids)) > 1:
                run_is_complete_for_all = False
                print(
                    (
                        "WARNING: Skipping run={run}, run_index={run_idx} because run IDs differ across parties: {ids}"
                    ).format(run=run_name, run_idx=run_idx + 1, ids=run_ids_at_index),
                    file=sys.stderr,
                )

        if run_is_complete_for_all:
            complete_indexes.append(run_idx)

    return complete_indexes


def expected_party_count_for_run(run_name: str) -> int:
    if run_name.endswith("-4p"):
        return 4
    if run_name.endswith("-5p"):
        return 5
    return 0


def select_party_files_for_run(
    all_party_runs: Dict[str, Dict[str, List[List[MetricLine]]]],
    run_name: str,
    party_files: List[str],
) -> List[str]:
    selected_party_files = [
        party_file for party_file in party_files if len(all_party_runs[party_file][run_name]) > 0
    ]

    expected_party_count = expected_party_count_for_run(run_name)
    if expected_party_count and len(selected_party_files) != expected_party_count:
        print(
            (
                "WARNING: run={run} expected {expected} participating party files based on run name but found {found}: {files}"
            ).format(
                run=run_name,
                expected=expected_party_count,
                found=len(selected_party_files),
                files=selected_party_files,
            ),
            file=sys.stderr,
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
            print(
                (
                    "WARNING: Name mismatch across parties in run={run}, run_index={run_idx}, "
                    "operation_index={op_idx}: names={names}"
                ).format(
                    run=run_name,
                    run_idx=source_run_index + 1,
                    op_idx=op_idx + 1,
                    names=sorted(names),
                ),
                file=sys.stderr,
            )

        num_sessions_values = [metric_line.num_sessions for _, metric_line in per_party_metrics]
        if len(set(num_sessions_values)) > 1:
            print(
                (
                    "ERROR: num_sessions mismatch across parties in run={run}, run_index={run_idx}, "
                    "operation_index={op_idx}: values={values}"
                ).format(
                    run=run_name,
                    run_idx=source_run_index + 1,
                    op_idx=op_idx + 1,
                    values=num_sessions_values,
                ),
                file=sys.stderr,
            )

        num_rounds_values = [metric_line.num_rounds for _, metric_line in per_party_metrics]
        if len(set(num_rounds_values)) > 1:
            print(
                (
                    "ERROR: num_rounds mismatch across parties in run={run}, run_index={run_idx}, "
                    "operation_index={op_idx}: values={values}"
                ).format(
                    run=run_name,
                    run_idx=source_run_index + 1,
                    op_idx=op_idx + 1,
                    values=num_rounds_values,
                ),
                file=sys.stderr,
            )

        network_sent_values = [metric_line.network_sent for _, metric_line in per_party_metrics]
        network_received_values = [metric_line.network_received for _, metric_line in per_party_metrics]
        time_active_values = [metric_line.time_active for _, metric_line in per_party_metrics]

        for party_file, metric_line in per_party_metrics:
            if metric_line.network_sent != metric_line.network_received:
                print(
                    (
                        "WARNING: network_sent != network_received in {path}, run={run}, run_index={run_idx}, "
                        "operation_index={op_idx}: sent={sent}, received={received}"
                    ).format(
                        path=party_file,
                        run=run_name,
                        run_idx=source_run_index + 1,
                        op_idx=op_idx + 1,
                        sent=metric_line.network_sent,
                        received=metric_line.network_received,
                    ),
                    file=sys.stderr,
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
                average(time_active_values),
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

    args = parser.parse_args()

    party_files = sorted(glob.glob(os.path.join(args.input_dir, args.pattern)))
    if not party_files:
        print(
            f"ERROR: No files found matching {args.pattern} in directory {args.input_dir}",
            file=sys.stderr,
        )
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

    tfhe_complete_runs_count = sum(
        len(tfhe_complete_runs_by_name[tfhe_run_name]) for tfhe_run_name in TFHE_RUN_NAMES
    )
    bgv_complete_runs = collect_complete_run_indexes(
        all_party_runs=all_party_runs,
        all_party_run_ids=all_party_run_ids,
        run_name=BGV_RUN_NAME,
        party_files=party_files,
    )

    tfhe_rows: List[List[object]] = []
    tfhe_complete_run_index = 1
    for tfhe_run_name in TFHE_RUN_NAMES:
        tfhe_party_files = tfhe_party_files_by_name[tfhe_run_name]
        for run_idx in tfhe_complete_runs_by_name[tfhe_run_name]:
            tfhe_rows.extend(
                aggregate_run(
                    run_name=tfhe_run_name,
                    source_run_index=run_idx,
                    complete_run_index=tfhe_complete_run_index,
                    party_files=tfhe_party_files,
                    all_party_runs=all_party_runs,
                    spread_warn_threshold=args.spread_warning_threshold,
                )
            )
            tfhe_complete_run_index += 1

    bgv_rows: List[List[object]] = []
    for complete_idx, run_idx in enumerate(bgv_complete_runs, start=1):
        bgv_rows.extend(
            aggregate_run(
                run_name=BGV_RUN_NAME,
                source_run_index=run_idx,
                complete_run_index=complete_idx,
                party_files=party_files,
                all_party_runs=all_party_runs,
                spread_warn_threshold=args.spread_warning_threshold,
            )
        )

    os.makedirs(args.output_dir, exist_ok=True)
    tfhe_output_path = os.path.join(args.output_dir, f"TFHE_{num_parties}_{args.output_suffix}.csv")
    bgv_output_path = os.path.join(args.output_dir, f"BGV_{num_parties}_{args.output_suffix}.csv")

    write_csv(tfhe_output_path, tfhe_rows)
    write_csv(bgv_output_path, bgv_rows)

    print(f"Parsed {num_parties} party files.")
    print(f"Complete TFHE runs: {tfhe_complete_runs_count}")
    print(f"Complete BGV runs: {len(bgv_complete_runs)}")
    print(f"Wrote TFHE CSV: {tfhe_output_path}")
    print(f"Wrote BGV CSV: {bgv_output_path}")


if __name__ == "__main__":
    main()