#!/usr/bin/env python3
"""Parse session_stats from per-run folders and emit aggregated CSVs.

Layout expected at ``input_dir`` (the campaign folder produced by
``threshold-test-params.sh`` or the local archive scp'd back by the
``bench_nist`` shutdown script):

    <input_dir>/
        <experiment_name>_<timestamp>/
            BENCH_PARAMS.txt
            session_stats_<i>.txt    (one per party)
        <experiment_name>-mem_<timestamp>/        (optional, peak-mem source)
            BENCH_PARAMS.txt
            session_stats_<i>.txt
        ...

Each per-run subfolder is one chronologically-distinct run. ``BENCH_PARAMS.txt``
declares the run's identity and the operation schedule (``PROTOCOL``,
``SESSION_TYPE``, ``HAS_PRSS_INIT`` / ``HAS_CRS`` / ``HAS_RESHARE``,
``DDEC_MODES``). The ``session_stats_*.txt`` files are flat lists of
``name=...,role=...,...`` metric lines in the order the parties emitted them
(which matches the operation schedule, so matching is positional).

Output (one set per invocation, written next to the campaign folder or to
``--output-dir``):

    CRS_<suffix>.csv
    TFHE_KeyGen_<suffix>.csv
    TFHE_Reshare_<suffix>.csv
    TFHE_TDecOne_<suffix>.csv   (noise-flood DDEC)
    TFHE_TDecTwo_<suffix>.csv   (bit-dec DDEC)
    BGV_KeyGen_<suffix>.csv
    BGV_TDec_<suffix>.csv

CSV files for run types absent from the campaign (e.g. no BGV run for a
``bench_nist`` TFHE-only campaign) are written with just the header row.
"""

import argparse
import csv
import glob
import logging
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# TFHE message types and their bit widths. bool is reported with bit_width = 1.
# Both the operation-schedule builder and the TDec row emitter iterate
# TFHE_TYPES, so this list must match the DDEC loop in the bench scripts
# (kms tfhe_reproducible_common.sh / bench_nist tfhe_bench_common.sh).
TFHE_TYPES = ["bool", "u4", "u8", "u16", "u32", "u64"]
TFHE_TYPE_TO_BIT_WIDTH: Dict[str, int] = {
    "bool": 1,
    "u4": 4,
    "u8": 8,
    "u16": 16,
    "u32": 32,
    "u64": 64,
}

# Parallelism factors of the BGV ``DDEC_PARALLEL_N`` benchmark lines, one row
# per factor in the BGV TDec CSV.
BGV_DDEC_PARALLEL_FACTORS = [1, 2, 4, 8, 16, 32]


# ---------------------------------------------------------------------------
# Parameter set -> bits per LWE block
# ---------------------------------------------------------------------------
#
# A TFHE radix ciphertext is a vector of LWE ciphertexts, one per "block". The
# number of bits a block carries is determined by the parameter set's
# message_modulus: bits_per_block = log2(message_modulus). Two groups across
# the parameter sets the kms scripts can use (see
# core/threshold-execution/src/tfhe_internals/parameters.rs::to_param, and the
# raw MessageModulus values in raw_parameters.rs):
#
#   * NIST_PARAMS_P8_* (4 variants): MessageModulus = 2 -> 1 bit / block
#   * Everything else (NIST_PARAMS_P32_*, BC_PARAMS*, BC_PARAMS_NIGEL*,
#     PARAMS_TEST_BK_SNS):              MessageModulus = 4 -> 2 bits / block
#
# So a u64 message is 64 LWE blocks under P8 params but only 32 under
# everything else. ``bool`` is always one LWE block regardless of params.
# Mirrors the kms helper ``fhe_types_to_num_blocks`` in core/grpc/src/rpc_types.rs.
PARAMS_TO_BITS_PER_BLOCK: Dict[str, int] = {
    "nist-params-p8-no-sns-fglwe": 1,
    "nist-params-p8-sns-fglwe":    1,
    "nist-params-p8-no-sns-lwe":   1,
    "nist-params-p8-sns-lwe":      1,
    "nist-params-p32-no-sns-fglwe": 2,
    "nist-params-p32-sns-fglwe":    2,
    "nist-params-p32-no-sns-lwe":   2,
    "nist-params-p32-sns-lwe":      2,
    "bc-params-no-sns":         2,
    "bc-params-sns":            2,
    "bc-params-nigel-no-sns":   2,
    "bc-params-nigel-sns":      2,
    "params-test-bk-sns":       2,
}


def _bits_per_block(params: str) -> int:
    """Bits per LWE block for ``params``.

    Raises ``ValueError`` if ``params`` isn't in ``PARAMS_TO_BITS_PER_BLOCK``;
    we refuse to guess because the value directly affects every TDec
    throughput cell in the CSV (LWE blocks/sec). Add the new parameter set to
    the table — read its ``MessageModulus`` from
    ``core/threshold-execution/src/tfhe_internals/parameters.rs::to_param``
    and store ``log2(message_modulus)``.
    """
    bpb = PARAMS_TO_BITS_PER_BLOCK.get(params.lower())
    if bpb is None:
        raise ValueError(
            f"Unknown PARAMS={params!r}; cannot compute LWE-block throughput. "
            f"Add it to PARAMS_TO_BITS_PER_BLOCK in session-stats-parser.py "
            f"(known values: {sorted(PARAMS_TO_BITS_PER_BLOCK)})."
        )
    return bpb


def _num_blocks(bit_width: int, bits_per_block: int) -> int:
    """Number of LWE blocks a message of ``bit_width`` decomposes into.

    ``bool`` is always one block regardless of bits_per_block. All other
    supported widths (4, 8, 16, 32, 64) are clean multiples of 1 or 2 bits;
    we use ceil-div as a safety net if an odd width is ever added.
    """
    if bit_width <= 1:
        return 1
    return -(-bit_width // bits_per_block)


# ---------------------------------------------------------------------------
# BENCH_PARAMS.txt parsing
# ---------------------------------------------------------------------------


@dataclass
class BenchParams:
    """Identity + operation schedule of one run, read from BENCH_PARAMS.txt.

    All non-trivial defaults reflect what the kms reproducible / bench_nist
    scripts write; missing fields fall back rather than abort so a partially
    populated BENCH_PARAMS.txt (e.g. from an early draft writer) still parses.
    """

    experiment_name: str
    protocol: str  # "tfhe" or "bgv"
    session_type: str  # "small" / "large" for tfhe; "" for bgv
    num_parties: int
    threshold: int
    malicious: bool
    measure_memory: bool
    num_ctxts: int
    num_sessions: int
    percentage_offline: int
    params: str  # TFHE parameter set name; "" for bgv
    ddec_modes: List[str]  # e.g. ["noise-flood-small", "bit-dec-small"]
    # CRS sweep: when non-empty, the run emits one CRS_GEN_<UPPER_PARAMS>
    # line per entry in order (used by the standalone crs_reproducible.sh
    # script). When empty and ``has_crs`` is set, the run emits a single
    # plain ``CRS_GEN`` line using ``params``.
    crs_params: List[str]
    has_prss_init: bool
    has_dkg: bool
    has_crs: bool
    has_reshare: bool


def _truthy(value: str, default: bool) -> bool:
    """Parse a BENCH_PARAMS.txt boolean field. ``""`` falls back to ``default``."""
    value = value.strip()
    if not value:
        return default
    return value.lower() not in ("0", "false", "no", "off")


def _maybe_int(value: str, default: int) -> int:
    value = value.strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_bench_params(folder: str) -> Optional[BenchParams]:
    """Read ``<folder>/BENCH_PARAMS.txt`` into a ``BenchParams``.

    Returns ``None`` if the file is absent or has no recognisable key/value
    lines. Header lines (``=== ... ===``), blank lines, and comments are
    skipped; unknown keys are ignored to keep the format forward-compatible.
    """
    path = os.path.join(folder, "BENCH_PARAMS.txt")
    if not os.path.isfile(path):
        return None

    raw: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("===") or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            raw[key.strip()] = value.strip()

    if not raw:
        return None

    protocol = raw.get("PROTOCOL", "tfhe").lower()
    # TFHE runs do CRS + Reshare; BGV doesn't. The script-side writer can
    # override either flag if a particular run skips one of those phases.
    has_crs_default = protocol == "tfhe"
    has_reshare_default = protocol == "tfhe"

    ddec_modes_raw = raw.get("DDEC_MODES", "")
    ddec_modes = [m for m in ddec_modes_raw.split() if m]

    crs_params_raw = raw.get("CRS_PARAMS", "")
    crs_params = [p for p in crs_params_raw.split() if p]

    return BenchParams(
        experiment_name=raw.get("EXPERIMENT_NAME", os.path.basename(folder)),
        protocol=protocol,
        session_type=raw.get("SESSION_TYPE", "").lower(),
        num_parties=_maybe_int(raw.get("NUM_PARTIES", ""), 0),
        threshold=_maybe_int(raw.get("THRESHOLD", ""), 1),
        malicious=_truthy(raw.get("MALICIOUS", ""), False),
        measure_memory=_truthy(raw.get("MEASURE_MEMORY", ""), False),
        num_ctxts=_maybe_int(raw.get("NUM_CTXTS", ""), 10),
        num_sessions=_maybe_int(raw.get("NUM_SESSIONS", ""), 5),
        percentage_offline=_maybe_int(raw.get("PERCENTAGE_OFFLINE", ""), 100),
        params=raw.get("PARAMS", ""),
        ddec_modes=ddec_modes,
        crs_params=crs_params,
        has_prss_init=_truthy(raw.get("HAS_PRSS_INIT", ""), True),
        # has_dkg defaults to True for backward compatibility with older
        # BENCH_PARAMS.txt files that pre-date the standalone CRS script.
        # The new crs_reproducible.sh writes HAS_DKG=0 explicitly.
        has_dkg=_truthy(raw.get("HAS_DKG", ""), True),
        has_crs=_truthy(raw.get("HAS_CRS", ""), has_crs_default),
        has_reshare=_truthy(raw.get("HAS_RESHARE", ""), has_reshare_default),
    )


# ---------------------------------------------------------------------------
# Expected operation schedule (positional matching)
# ---------------------------------------------------------------------------
#
# Each metric line in session_stats_<i>.txt is positionally matched to a label
# in the expected schedule. The schedule is derived from the BENCH_PARAMS
# feature flags so the same parser works across the kms reproducible scripts
# (which skip PRSS init for large sessions and never run CRS/Reshare for BGV)
# and the bench_nist scripts (which always run PRSS init and now also run
# CRS/Reshare for TFHE).


def _mode_to_label_prefix(mode: str) -> str:
    """Convert a ddec mode like ``noise-flood-small`` to label prefix ``NOISE_FLOOD_SMALL``."""
    return mode.upper().replace("-", "_")


def _crs_label_for(params: str) -> str:
    """Schedule label for a CRS_GEN line tied to a specific parameter set.

    Used when CRS gen is swept over multiple parameter sets in one run
    (standalone ``crs_reproducible.sh``); the single-CRS case keeps the
    plain ``CRS_GEN`` label for backward compatibility.
    """
    return f"CRS_GEN_{params.upper().replace('-', '_')}"


def _build_tfhe_labels(bp: BenchParams) -> List[str]:
    labels: List[str] = []
    if bp.has_prss_init:
        labels.extend(["PRSS_INIT_Z64", "PRSS_INIT_Z128"])
    if bp.has_dkg:
        labels.extend(["DKG_PREPROC", "DKG"])
    if bp.has_crs:
        if bp.crs_params:
            # CRS sweep: one labeled CRS_GEN per parameter set, in order.
            for p in bp.crs_params:
                labels.append(_crs_label_for(p))
        else:
            # Single CRS gen (existing TFHE flow before the standalone
            # script was extracted; kept for backward compatibility).
            labels.append("CRS_GEN")
    if bp.has_reshare:
        # Reshare emits two consecutive session-stats lines: the preprocessing
        # phase followed by the online phase.
        labels.extend(["RESHARE_PREPROC", "RESHARE"])
    for mode in bp.ddec_modes:
        prefix = _mode_to_label_prefix(mode)
        for tfhe_type in TFHE_TYPES:
            labels.append(f"{prefix}_{tfhe_type}_PREPROC")
            labels.append(f"{prefix}_{tfhe_type}_DDEC")
    return labels


def _build_bgv_labels(bp: BenchParams) -> List[str]:
    labels: List[str] = []
    if bp.has_prss_init:
        labels.extend(["PRSS_INIT_LEVEL_ONE", "PRSS_INIT_LEVEL_KSW"])
    if bp.has_dkg:
        labels.extend(["DKG_PREPROC", "DKG"])
    for parallel_n in BGV_DDEC_PARALLEL_FACTORS:
        labels.append(f"DDEC_PARALLEL_{parallel_n}")
    return labels


def expected_labels(bp: BenchParams) -> List[str]:
    if bp.protocol == "tfhe":
        return _build_tfhe_labels(bp)
    if bp.protocol == "bgv":
        return _build_bgv_labels(bp)
    raise ValueError(f"Unknown PROTOCOL={bp.protocol!r} in BENCH_PARAMS.txt")


# ---------------------------------------------------------------------------
# session_stats parsing
# ---------------------------------------------------------------------------


@dataclass
class MetricLine:
    name: str
    role: int
    num_sessions: int
    num_rounds: int
    network_sent: int
    network_received: int
    time_active: int
    # ``peak_mem(B)`` is only emitted when the party binary was compiled with
    # the ``measure_memory`` feature. ``None`` on lines from non-mem runs.
    peak_mem_B: Optional[int] = None


def parse_metric_line(raw_line: str) -> MetricLine:
    fields: Dict[str, str] = {}
    for chunk in raw_line.strip().split(","):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        fields[key.strip()] = value.strip()

    try:
        peak_mem_raw = fields.get("peak_mem(B)")
        return MetricLine(
            name=fields["name"],
            role=int(fields["role"]),
            num_sessions=int(fields["num_sessions"]),
            num_rounds=int(fields["num_rounds"]),
            network_sent=int(fields["network_sent(B)"]),
            network_received=int(fields["network_received(B)"]),
            time_active=int(fields["time_active(ms)"]),
            peak_mem_B=int(peak_mem_raw) if peak_mem_raw is not None else None,
        )
    except KeyError as exc:
        raise ValueError(f"Missing expected key {exc} in line: {raw_line.strip()}") from exc


def parse_session_stats_file(path: str) -> List[MetricLine]:
    """Read a flat ``session_stats_<i>.txt`` file as one run's metric lines.

    Blank lines and any legacy ``NEW_RUN:`` header lines are skipped so files
    that were written under the previous accumulating layout (one file per
    cluster lifecycle, multiple NEW_RUN sections back-to-back) still parse
    cleanly — only the metric lines in the file are returned, in order.
    """
    out: List[MetricLine] = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("NEW_RUN:"):
                continue
            if line.startswith("name="):
                out.append(parse_metric_line(line))
    return out


# ---------------------------------------------------------------------------
# Cross-party aggregation
# ---------------------------------------------------------------------------


@dataclass
class AggregatedOperation:
    """Cross-party averaged metrics for one operation in one run.

    ``avg_time_active_ms``, ``avg_num_rounds``, ``avg_network_sent_B`` and
    ``avg_network_received_B`` are divided by ``num_ctxts_for_label(label)``,
    so they are per-ciphertext for DDEC / PREPROC labels (divisor =
    ``bp.num_ctxts``) and per-operation for everything else (divisor = 1).

    ``max_peak_mem_B`` / ``avg_peak_mem_B`` are populated only when every
    party file for this operation reported a ``peak_mem(B)`` field — i.e.
    only on ``-mem`` runs. Neither is divided by num_ctxts (mem runs use
    NUM_CTXTS=1 since the peak allocator is far too slow for batches).
    """

    label: str
    reported_name: str
    avg_num_sessions: float
    avg_num_rounds: int
    avg_network_sent_B: float
    avg_network_received_B: float
    avg_time_active_ms: float
    max_peak_mem_B: Optional[float] = None
    avg_peak_mem_B: Optional[float] = None


def _num_ctxts_for_label(label: str, bench_num_ctxts: int) -> int:
    """Number of ciphertexts processed by an operation.

    Decrypt-related operations (PREPROC, DDEC, DDEC_PARALLEL) each process
    ``bench_num_ctxts`` ciphertexts. RESHARE_PREPROC and RESHARE are
    reshare-only and not per-ciphertext. All other operations return 1.
    """
    if label.startswith("RESHARE"):
        return 1
    if "PREPROC" in label and "DKG" not in label:
        return bench_num_ctxts
    if "DDEC" in label:
        return bench_num_ctxts
    return 1


def _average(values: List[int]) -> float:
    return float(sum(values)) / float(len(values))


def _relative_spread(values: List[int]) -> float:
    if not values:
        return 0.0
    mean_value = _average(values)
    denominator = abs(mean_value)
    if denominator < 1.0:
        denominator = 1.0
    return float(max(values) - min(values)) / denominator


def _warn_if_large_spread(
    experiment_name: str,
    operation_label: str,
    metric_name: str,
    values: List[int],
    threshold: float,
) -> None:
    spread = _relative_spread(values)
    if spread > threshold:
        logger.warning(
            "Large spread for %s across parties in run=%s, operation=%s: "
            "min=%s, max=%s, mean=%.3f, rel_spread=%.3f",
            metric_name,
            experiment_name,
            operation_label,
            min(values),
            max(values),
            _average(values),
            spread,
        )


def _select_party_files(
    folder: str,
    bp: BenchParams,
    expected_len: int,
) -> List[str]:
    """Choose which party files participate in the cross-party average.

    On malicious runs we expect one party's log to be short or malformed.
    We rank by the number of well-formed metric lines and keep the top
    ``num_parties - 1`` files. On honest runs we keep every file that has
    the expected line count; mismatches are warned about and the run is
    dropped by the caller.
    """
    party_files = sorted(glob.glob(os.path.join(folder, "session_stats_*.txt")))
    if not party_files:
        return []

    if bp.malicious and bp.num_parties > 1:
        target = bp.num_parties - 1
        if len(party_files) > target:
            # Rank by metric-line count, keep the top ``target`` files.
            ranked = sorted(
                party_files,
                key=lambda p: len(parse_session_stats_file(p)),
                reverse=True,
            )
            kept = ranked[:target]
            dropped = ranked[target:]
            logger.warning(
                "run=%s identified as malicious; dropping %s from averaging",
                bp.experiment_name,
                dropped,
            )
            party_files = kept

    return party_files


def aggregate_run(
    folder: str,
    bp: BenchParams,
    spread_threshold: float,
) -> Optional[List[AggregatedOperation]]:
    """Aggregate one run's metric lines into per-operation, cross-party averages.

    Returns ``None`` if the run is unusable (no party files, party-file metric
    counts don't match the expected schedule, etc.); the caller drops the run.
    """
    labels = expected_labels(bp)
    expected_len = len(labels)

    party_files = _select_party_files(folder, bp, expected_len)
    if not party_files:
        logger.warning("Run %s: no session_stats files in %s; skipping", bp.experiment_name, folder)
        return None

    per_party_lines: List[List[MetricLine]] = []
    for path in party_files:
        lines = parse_session_stats_file(path)
        if len(lines) != expected_len:
            logger.warning(
                "Run %s: party file %s has %d metric lines but %d expected; skipping run.",
                bp.experiment_name,
                path,
                len(lines),
                expected_len,
            )
            return None
        per_party_lines.append(lines)

    aggregated: List[AggregatedOperation] = []
    for op_idx, label in enumerate(labels):
        op_lines = [per_party_lines[p][op_idx] for p in range(len(per_party_lines))]

        # Sanity: every party should report the same span name and the same
        # session/round counts for one operation. Spread on network/time is
        # expected (party-local measurement) but worth warning if huge.
        names = {ml.name for ml in op_lines}
        if len(names) > 1:
            logger.warning(
                "Run %s op %s: name mismatch across parties: %s",
                bp.experiment_name,
                label,
                sorted(names),
            )

        num_sessions_values = [ml.num_sessions for ml in op_lines]
        if len(set(num_sessions_values)) > 1:
            logger.error(
                "Run %s op %s: num_sessions mismatch across parties: %s",
                bp.experiment_name,
                label,
                num_sessions_values,
            )

        num_rounds_values = [ml.num_rounds for ml in op_lines]
        if len(set(num_rounds_values)) > 1:
            logger.error(
                "Run %s op %s: num_rounds mismatch across parties: %s",
                bp.experiment_name,
                label,
                num_rounds_values,
            )

        net_sent_values = [ml.network_sent for ml in op_lines]
        net_recv_values = [ml.network_received for ml in op_lines]
        time_values = [ml.time_active for ml in op_lines]

        for path, ml in zip(party_files, op_lines):
            if ml.network_sent != ml.network_received:
                logger.warning(
                    "Run %s op %s in %s: network_sent != network_received: sent=%s, recv=%s",
                    bp.experiment_name, label, path,
                    ml.network_sent, ml.network_received,
                )

        for metric, vals in (
            ("network_sent(B)", net_sent_values),
            ("network_received(B)", net_recv_values),
            ("time_active(ms)", time_values),
        ):
            _warn_if_large_spread(bp.experiment_name, label, metric, vals, spread_threshold)

        peak_mem_values = [ml.peak_mem_B for ml in op_lines if ml.peak_mem_B is not None]
        if peak_mem_values and len(peak_mem_values) == len(op_lines):
            max_peak_mem_B: Optional[float] = float(max(peak_mem_values))
            avg_peak_mem_B: Optional[float] = _average(peak_mem_values)
        else:
            if peak_mem_values:
                logger.warning(
                    "Run %s op %s: partial peak_mem reporting (%d/%d parties); "
                    "dropping peak_mem for this operation.",
                    bp.experiment_name, label,
                    len(peak_mem_values), len(op_lines),
                )
            max_peak_mem_B = None
            avg_peak_mem_B = None

        num_ctxts = _num_ctxts_for_label(label, bp.num_ctxts)
        aggregated.append(
            AggregatedOperation(
                label=label,
                reported_name=op_lines[0].name,
                # num_sessions is intentionally NOT divided.
                avg_num_sessions=_average(num_sessions_values),
                # Rounds are integer in practice; round to keep the CSV "rounds"
                # cells integer for offline and online alike.
                avg_num_rounds=int(round(_average(num_rounds_values) / num_ctxts)),
                avg_network_sent_B=_average(net_sent_values) / num_ctxts,
                avg_network_received_B=_average(net_recv_values) / num_ctxts,
                avg_time_active_ms=_average(time_values) / num_ctxts,
                # Peak memory is intentionally NOT divided.
                max_peak_mem_B=max_peak_mem_B,
                avg_peak_mem_B=avg_peak_mem_B,
            )
        )

    return aggregated


# ---------------------------------------------------------------------------
# Run discovery + mem pairing
# ---------------------------------------------------------------------------


@dataclass
class Run:
    folder: str
    params: BenchParams
    aggregates: List[AggregatedOperation]


def discover_runs(input_dir: str, spread_threshold: float) -> List[Run]:
    """Scan ``input_dir`` for per-run subfolders and aggregate each one."""
    runs: List[Run] = []
    for entry in sorted(os.listdir(input_dir)):
        full = os.path.join(input_dir, entry)
        if not os.path.isdir(full):
            continue
        bp = parse_bench_params(full)
        if bp is None:
            logger.warning("Skipping %s: no readable BENCH_PARAMS.txt", full)
            continue
        aggs = aggregate_run(full, bp, spread_threshold)
        if aggs is None:
            continue
        runs.append(Run(folder=full, params=bp, aggregates=aggs))
    return runs


def _base_experiment_name(name: str) -> str:
    """Strip the ``-mem`` suffix that distinguishes a memory campaign from
    its non-mem twin (the parser pairs them to fill the memory CSV cells).
    """
    if name.endswith("-mem"):
        return name[: -len("-mem")]
    return name


def split_runs(runs: List[Run]) -> Tuple[List[Run], Dict[str, Run]]:
    """Partition runs into (row-producing non-mem runs, mem index).

    ``mem_index[base_experiment_name]`` is the matching mem-run aggregate for
    that experiment, or absent when no mem run was found.
    """
    non_mem: List[Run] = []
    mem: Dict[str, Run] = {}
    for r in runs:
        if r.params.measure_memory:
            base = _base_experiment_name(r.params.experiment_name)
            if base in mem:
                logger.warning(
                    "Two mem runs share base experiment name %s; keeping the first.",
                    base,
                )
                continue
            mem[base] = r
        else:
            non_mem.append(r)
    return non_mem, mem


def _find_operation(aggs: List[AggregatedOperation], label: str) -> Optional[AggregatedOperation]:
    for op in aggs:
        if op.label == label:
            return op
    return None


# ---------------------------------------------------------------------------
# Memory cell helpers (peak_mem(B) -> kBytes, with -1 sentinel when missing)
# ---------------------------------------------------------------------------


def _b_to_kb(value: Optional[float]) -> float:
    if value is None:
        return -1
    return value / 1024.0


def _peak_mem_kb_for(
    label: str,
    mem_run: Optional[Run],
) -> Tuple[float, float]:
    """``(max_peak_mem_kB, avg_peak_mem_kB)`` for ``label`` in the mem twin.

    Both default to ``-1`` when no mem twin exists, when the label is missing
    in the mem twin's aggregates, or when the mem aggregate could not compute
    a value (partial party reporting).
    """
    if mem_run is None:
        return -1, -1
    op = _find_operation(mem_run.aggregates, label)
    if op is None:
        return -1, -1
    return _b_to_kb(op.max_peak_mem_B), _b_to_kb(op.avg_peak_mem_B)


# ---------------------------------------------------------------------------
# CSV emission
# ---------------------------------------------------------------------------
#
# All header rows keep the original column shape (so any existing downstream
# tooling that reads the CSVs by column index keeps working) and append the
# run-identity columns from BENCH_PARAMS.txt at the end via ``META_HEADERS``.


META_HEADERS = [
    "experiment_name",
    "session_type",
    "params",
    "num_sessions",
    "percentage_offline",
    "num_ctxts_per_batch",
]


def _meta_cells(bp: BenchParams) -> List[object]:
    return [
        bp.experiment_name,
        bp.session_type,
        bp.params,
        bp.num_sessions,
        bp.percentage_offline,
        bp.num_ctxts,
    ]


def _meta_cells_with_params(bp: BenchParams, override_params: str) -> List[object]:
    """Like ``_meta_cells`` but with ``bp.params`` replaced by
    ``override_params``. Used for CRS sweep rows where each row in the same
    run carries its own param-set name in the ``params`` column.
    """
    return [
        bp.experiment_name,
        bp.session_type,
        override_params,
        bp.num_sessions,
        bp.percentage_offline,
        bp.num_ctxts,
    ]


CRS_HEADERS = [
    "malicious",
    "num_parties",
    "avg_latency_ms",
    "rounds",
    "avg_bytes_sent_per_party",
    "avg_bytes_received_per_party",
    "max_memory_kBytes",
] + META_HEADERS


# KeyGen, Reshare, BGV_KeyGen — same shape, different label pairs.
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
] + META_HEADERS


# Both TFHE TDec CSVs share this header (TDecOne = noise-flood, TDecTwo = bit-dec).
TDEC_HEADERS = [
    "malicious",
    "num_parties",
    "num_ctxt",  # number of LWE ciphertexts (blocks) per message — depends on PARAMS
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
] + META_HEADERS


# BGV decryption is single-phase (one ``DDEC_PARALLEL_N`` line per parallelism
# factor) so it gets a flatter CSV than the TFHE TDec ones.
BGV_TDEC_HEADERS = [
    "malicious",
    "num_parties",
    "num_ctxt",  # parallelism factor N
    "avg_latency_ms",
    "throughput_per_sec",
    "rounds",
    "avg_bytes_sent_per_party",
    "avg_bytes_received_per_party",
    "max_memory_kBytes",
    "avg_mem_kBytes",
] + META_HEADERS


def _has_offline_phase(preproc: AggregatedOperation) -> bool:
    """An offline phase exists for a row iff its PREPROC line did real work,
    detected here by ``num_rounds != 0``."""
    return preproc.avg_num_rounds != 0


def _throughput_lwe_per_sec(num_blocks: int, per_radix_latency_ms: float) -> float:
    """LWE-blocks-per-second throughput.

    The ``per_radix_latency_ms`` is the time for one full radix ciphertext
    (covering all ``num_blocks`` LWE-block decryptions). Multiplying by
    ``num_blocks`` converts to LWE-blocks-per-second; multiplying by 1000
    converts ms to seconds.
    """
    if per_radix_latency_ms <= 0:
        return 0.0
    return num_blocks * 1000.0 / per_radix_latency_ms


def _two_phase_row(
    bp: BenchParams,
    preproc: AggregatedOperation,
    online: AggregatedOperation,
    mem_run: Optional[Run],
) -> List[object]:
    """Row for the KeyGen / Reshare / BGV_KeyGen CSVs.

    Memory cells are filled from ``mem_run`` when available and default to
    ``-1`` otherwise. Offline cells become ``-1`` when the preproc line has
    ``num_rounds == 0`` (means the run skipped real preprocessing).

    DKG preprocessing is often run on only a subset of the offline material
    (``percentage_offline < 100``) to keep wall-clock manageable. The session
    stats then report the time/rounds/bytes for that subset, so we scale the
    four offline metric cells by ``100 / percentage_offline`` to project to a
    full offline phase. Rounds stays integer. Memory cells are NOT scaled —
    peak allocator usage doesn't grow with the offline workload count.
    Scaling only applies to ``DKG_PREPROC``; other preproc labels (Reshare,
    DDEC preproc) already run their full offline phase.
    """
    offline_present = _has_offline_phase(preproc)
    offline_max_mem, offline_avg_mem = _peak_mem_kb_for(preproc.label, mem_run)
    online_max_mem, online_avg_mem = _peak_mem_kb_for(online.label, mem_run)

    if preproc.label == "DKG_PREPROC" and bp.percentage_offline > 0:
        offline_scale = 100.0 / bp.percentage_offline
    else:
        offline_scale = 1.0
    offline_time = preproc.avg_time_active_ms * offline_scale
    offline_rounds = int(round(preproc.avg_num_rounds * offline_scale))
    offline_sent = preproc.avg_network_sent_B * offline_scale
    offline_recv = preproc.avg_network_received_B * offline_scale

    return [
        1 if bp.malicious else 0,
        bp.num_parties,
        offline_time if offline_present else -1,
        offline_rounds if offline_present else -1,
        offline_sent if offline_present else -1,
        offline_recv if offline_present else -1,
        offline_max_mem if offline_present else -1,
        offline_avg_mem if offline_present else -1,
        online.avg_time_active_ms,
        online.avg_num_rounds,
        online.avg_network_sent_B,
        online.avg_network_received_B,
        online_max_mem,
        online_avg_mem,
    ] + _meta_cells(bp)


def _tdec_one_row(
    bp: BenchParams,
    num_blocks: int,
    preproc: AggregatedOperation,
    ddec: AggregatedOperation,
    mem_run: Optional[Run],
) -> List[object]:
    """Row for ``TFHE_TDecOne_*`` (NOISE_FLOOD).

    Offline is the PREPROC line (``-1`` when its ``num_rounds`` is 0); online
    is the sum of PREPROC + DDEC (latency, rounds, bytes summed; throughput
    recomputed from the summed per-radix latency). ``num_blocks`` is the LWE
    ciphertext count for this message type under the run's parameter set; it
    goes into the ``num_ctxt`` column and into the throughput math (LWE blocks
    per second = ``num_blocks * 1000 / per_radix_latency_ms``).
    """
    offline_present = _has_offline_phase(preproc)
    online_latency_ms = preproc.avg_time_active_ms + ddec.avg_time_active_ms
    online_rounds = preproc.avg_num_rounds + ddec.avg_num_rounds
    online_bytes_sent = preproc.avg_network_sent_B + ddec.avg_network_sent_B
    online_bytes_received = preproc.avg_network_received_B + ddec.avg_network_received_B
    offline_max_mem, _ = _peak_mem_kb_for(preproc.label, mem_run)
    ddec_max_mem, _ = _peak_mem_kb_for(ddec.label, mem_run)
    if offline_max_mem == -1 and ddec_max_mem == -1:
        online_max_mem: float = -1
    else:
        online_max_mem = max(offline_max_mem, ddec_max_mem)
    return [
        1 if bp.malicious else 0,
        bp.num_parties,
        num_blocks,
        preproc.avg_time_active_ms if offline_present else -1,
        _throughput_lwe_per_sec(num_blocks, preproc.avg_time_active_ms) if offline_present else -1,
        online_latency_ms,
        _throughput_lwe_per_sec(num_blocks, online_latency_ms),
        preproc.avg_num_rounds if offline_present else -1,
        online_rounds,
        preproc.avg_network_sent_B if offline_present else -1,
        preproc.avg_network_received_B if offline_present else -1,
        online_bytes_sent,
        online_bytes_received,
        offline_max_mem if offline_present else -1,
        online_max_mem,
    ] + _meta_cells(bp)


def _tdec_two_row(
    bp: BenchParams,
    num_blocks: int,
    preproc: AggregatedOperation,
    ddec: AggregatedOperation,
    mem_run: Optional[Run],
) -> List[object]:
    """Row for ``TFHE_TDecTwo_*`` (BIT_DEC).

    Offline is the PREPROC line (``-1`` when ``num_rounds`` is 0); online is
    the DDEC line. ``num_blocks`` is the LWE ciphertext count for this message
    type under the run's parameter set; it goes into the ``num_ctxt`` column
    and into the throughput math (LWE blocks per second = ``num_blocks * 1000
    / per_radix_latency_ms``).
    """
    offline_present = _has_offline_phase(preproc)
    offline_max_mem, _ = _peak_mem_kb_for(preproc.label, mem_run)
    online_max_mem, _ = _peak_mem_kb_for(ddec.label, mem_run)
    return [
        1 if bp.malicious else 0,
        bp.num_parties,
        num_blocks,
        preproc.avg_time_active_ms if offline_present else -1,
        _throughput_lwe_per_sec(num_blocks, preproc.avg_time_active_ms) if offline_present else -1,
        ddec.avg_time_active_ms,
        _throughput_lwe_per_sec(num_blocks, ddec.avg_time_active_ms),
        preproc.avg_num_rounds if offline_present else -1,
        ddec.avg_num_rounds,
        preproc.avg_network_sent_B if offline_present else -1,
        preproc.avg_network_received_B if offline_present else -1,
        ddec.avg_network_sent_B,
        ddec.avg_network_received_B,
        offline_max_mem if offline_present else -1,
        online_max_mem,
    ] + _meta_cells(bp)


def _write_csv(path: str, headers: List[str], rows: List[List[object]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)


def _emit_rows(
    runs: List[Run],
    mem_index: Dict[str, Run],
) -> Tuple[
    List[List[object]],  # crs
    List[List[object]],  # keygen (tfhe)
    List[List[object]],  # reshare
    List[List[object]],  # tdec_one
    List[List[object]],  # tdec_two
    List[List[object]],  # bgv_keygen
    List[List[object]],  # bgv_tdec
]:
    """Build the per-CSV row lists from the aggregated runs.

    Stable ordering: sort by (protocol, num_parties, experiment_name) so the
    CSVs come out in the same order across reruns of the same campaign.
    """
    crs_rows: List[List[object]] = []
    keygen_rows: List[List[object]] = []
    reshare_rows: List[List[object]] = []
    tdec_one_rows: List[List[object]] = []
    tdec_two_rows: List[List[object]] = []
    bgv_keygen_rows: List[List[object]] = []
    bgv_tdec_rows: List[List[object]] = []

    sorted_runs = sorted(
        runs,
        key=lambda r: (r.params.protocol, r.params.num_parties, r.params.experiment_name),
    )

    for r in sorted_runs:
        bp = r.params
        mem_run = mem_index.get(_base_experiment_name(bp.experiment_name))

        if bp.protocol == "tfhe":
            # CRS — either a single CRS_GEN (existing TFHE flow, uses
            # bp.params) or a sweep with one CRS_GEN_<P> per entry in
            # bp.crs_params (each row carries its own param name).
            if bp.has_crs:
                if bp.crs_params:
                    for p in bp.crs_params:
                        label = _crs_label_for(p)
                        crs_op = _find_operation(r.aggregates, label)
                        if crs_op is not None:
                            crs_max_mem, _ = _peak_mem_kb_for(label, mem_run)
                            crs_rows.append([
                                1 if bp.malicious else 0,
                                bp.num_parties,
                                crs_op.avg_time_active_ms,
                                crs_op.avg_num_rounds,
                                crs_op.avg_network_sent_B,
                                crs_op.avg_network_received_B,
                                crs_max_mem,
                            ] + _meta_cells_with_params(bp, p))
                else:
                    crs_op = _find_operation(r.aggregates, "CRS_GEN")
                    if crs_op is not None:
                        crs_max_mem, _ = _peak_mem_kb_for("CRS_GEN", mem_run)
                        crs_rows.append([
                            1 if bp.malicious else 0,
                            bp.num_parties,
                            crs_op.avg_time_active_ms,
                            crs_op.avg_num_rounds,
                            crs_op.avg_network_sent_B,
                            crs_op.avg_network_received_B,
                            crs_max_mem,
                        ] + _meta_cells(bp))

            # KeyGen (only when the run actually did DKG; standalone CRS runs
            # skip this).
            if bp.has_dkg:
                preproc = _find_operation(r.aggregates, "DKG_PREPROC")
                dkg = _find_operation(r.aggregates, "DKG")
                if preproc is not None and dkg is not None:
                    keygen_rows.append(_two_phase_row(bp, preproc, dkg, mem_run))

            # Reshare
            if bp.has_reshare:
                rp = _find_operation(r.aggregates, "RESHARE_PREPROC")
                rs = _find_operation(r.aggregates, "RESHARE")
                if rp is not None and rs is not None:
                    reshare_rows.append(_two_phase_row(bp, rp, rs, mem_run))

            # TDec — derive label prefix from session_type. Each TFHE run uses
            # one ddec mode pair (noise-flood-X + bit-dec-X) matching its
            # session type; we pick the matching uppercase prefix from
            # session_type and look up the per-tfhe-type PREPROC/DDEC pairs.
            # Skipped entirely when the run has no DDEC modes (e.g. standalone
            # CRS runs), which also lets PARAMS be empty without tripping the
            # LWE-block lookup.
            if bp.ddec_modes:
                session_upper = bp.session_type.upper() if bp.session_type else ""
                nf_prefix = f"NOISE_FLOOD_{session_upper}" if session_upper else None
                bd_prefix = f"BIT_DEC_{session_upper}" if session_upper else None

                # Bits per LWE block is parameter-set dependent. Compute once
                # per run; ``_num_blocks(bit_width, bits_per_block)`` converts
                # the message bit-width into the LWE-block count that goes into
                # both the ``num_ctxt`` column and the throughput math.
                bits_per_block = _bits_per_block(bp.params)

                for tfhe_type in TFHE_TYPES:
                    bit_width = TFHE_TYPE_TO_BIT_WIDTH[tfhe_type]
                    num_blocks = _num_blocks(bit_width, bits_per_block)

                    if nf_prefix is not None:
                        nf_pp = _find_operation(r.aggregates, f"{nf_prefix}_{tfhe_type}_PREPROC")
                        nf_dd = _find_operation(r.aggregates, f"{nf_prefix}_{tfhe_type}_DDEC")
                        if nf_pp is not None and nf_dd is not None:
                            tdec_one_rows.append(
                                _tdec_one_row(bp, num_blocks, nf_pp, nf_dd, mem_run)
                            )

                    if bd_prefix is not None:
                        bd_pp = _find_operation(r.aggregates, f"{bd_prefix}_{tfhe_type}_PREPROC")
                        bd_dd = _find_operation(r.aggregates, f"{bd_prefix}_{tfhe_type}_DDEC")
                        if bd_pp is not None and bd_dd is not None:
                            tdec_two_rows.append(
                                _tdec_two_row(bp, num_blocks, bd_pp, bd_dd, mem_run)
                            )

        elif bp.protocol == "bgv":
            # BGV KeyGen (only when the run actually did DKG).
            if bp.has_dkg:
                preproc = _find_operation(r.aggregates, "DKG_PREPROC")
                dkg = _find_operation(r.aggregates, "DKG")
                if preproc is not None and dkg is not None:
                    bgv_keygen_rows.append(_two_phase_row(bp, preproc, dkg, mem_run))

            # BGV TDec — one row per parallelism factor.
            for parallel_n in BGV_DDEC_PARALLEL_FACTORS:
                label = f"DDEC_PARALLEL_{parallel_n}"
                ddec = _find_operation(r.aggregates, label)
                if ddec is None:
                    continue
                throughput = (
                    parallel_n * 1000.0 / ddec.avg_time_active_ms
                    if ddec.avg_time_active_ms > 0
                    else 0.0
                )
                max_mem, avg_mem = _peak_mem_kb_for(label, mem_run)
                bgv_tdec_rows.append([
                    1 if bp.malicious else 0,
                    bp.num_parties,
                    parallel_n,
                    ddec.avg_time_active_ms,
                    throughput,
                    ddec.avg_num_rounds,
                    ddec.avg_network_sent_B,
                    ddec.avg_network_received_B,
                    max_mem,
                    avg_mem,
                ] + _meta_cells(bp))

    return (
        crs_rows, keygen_rows, reshare_rows,
        tdec_one_rows, tdec_two_rows,
        bgv_keygen_rows, bgv_tdec_rows,
    )


def write_campaign_csvs(
    output_dir: str,
    suffix: str,
    runs: List[Run],
    mem_index: Dict[str, Run],
) -> None:
    """Emit the seven CSVs for one campaign into ``output_dir``."""
    os.makedirs(output_dir, exist_ok=True)
    (crs, keygen, reshare, tdec_one, tdec_two, bgv_keygen, bgv_tdec) = _emit_rows(runs, mem_index)

    _write_csv(os.path.join(output_dir, f"CRS_{suffix}.csv"), CRS_HEADERS, crs)
    _write_csv(os.path.join(output_dir, f"TFHE_KeyGen_{suffix}.csv"), TWO_PHASE_HEADERS, keygen)
    _write_csv(os.path.join(output_dir, f"TFHE_Reshare_{suffix}.csv"), TWO_PHASE_HEADERS, reshare)
    _write_csv(os.path.join(output_dir, f"TFHE_TDecOne_{suffix}.csv"), TDEC_HEADERS, tdec_one)
    _write_csv(os.path.join(output_dir, f"TFHE_TDecTwo_{suffix}.csv"), TDEC_HEADERS, tdec_two)
    _write_csv(os.path.join(output_dir, f"BGV_KeyGen_{suffix}.csv"), TWO_PHASE_HEADERS, bgv_keygen)
    _write_csv(os.path.join(output_dir, f"BGV_TDec_{suffix}.csv"), BGV_TDEC_HEADERS, bgv_tdec)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Parse session_stats from per-run folders under <input-dir>, "
            "consume their BENCH_PARAMS.txt for run identity, aggregate "
            "across parties, and emit per-campaign CSVs (CRS, TFHE_KeyGen, "
            "TFHE_Reshare, TFHE_TDecOne, TFHE_TDecTwo, BGV_KeyGen, BGV_TDec) "
            "under --output-dir (defaults to <input-dir>)."
        )
    )
    parser.add_argument(
        "input_dir",
        help="Campaign folder containing per-run subfolders (each with BENCH_PARAMS.txt + session_stats_<i>.txt).",
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
        "--output-dir",
        default=None,
        help="Output directory for the CSVs. Default: same as input_dir.",
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

    if not os.path.isdir(args.input_dir):
        logger.error("input_dir %s is not a directory", args.input_dir)
        sys.exit(1)

    output_dir = args.output_dir if args.output_dir is not None else args.input_dir

    all_runs = discover_runs(args.input_dir, args.spread_warning_threshold)
    if not all_runs:
        logger.error("No usable per-run folders found under %s", args.input_dir)
        sys.exit(1)

    non_mem_runs, mem_index = split_runs(all_runs)
    write_campaign_csvs(output_dir, args.output_suffix, non_mem_runs, mem_index)
    print(
        f"Wrote CSVs to {output_dir} from {len(non_mem_runs)} row-producing runs "
        f"(+ {len(mem_index)} mem runs)"
    )


if __name__ == "__main__":
    main()
