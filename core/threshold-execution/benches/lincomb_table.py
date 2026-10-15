#!/usr/bin/env python3
"""Before/after tables of the lincomb benchmarks from criterion's saved estimates.

Usage: lincomb_table.py [target/criterion]

Reads every `new/estimates.json` under the criterion directory whose path contains a series token, groups
the series of one benchmark (same path with the series removed) and prints one table per comparison with the
median times and the speedups of the "after" series over the others:

  - lincomb backends: `Avx512Ifma` against `Scalar` (`MPC_LINCOMB_BACKEND=scalar`) and `fold` (the previous
    partial-decryption implementation, measured in the same run);
  - reconstruction: `Optimistic` (the optimistic path in front of the decoder) against `Decoder`
    (`MPC_RECONSTRUCT=decoder`).
"""
import json
import os
import re
import sys

# (title, series in column order, the "after" series, short label of the "after" series)
COMPARISONS = (
    ("linear combination backends", ("fold", "Scalar", "Avx512Ifma"), "Avx512Ifma", "ifma"),
    ("reconstruction of openings", ("Decoder", "Optimistic"), "Optimistic", "optimistic"),
)
ALL_SERIES = tuple(s for _, series, _, _ in COMPARISONS for s in series)
# Criterion writes group names with their '/' replaced by '_', so a series is a '_'- or '/'-delimited token.
SERIES_RE = re.compile(r"(?<=[_/])(" + "|".join(ALL_SERIES) + r")(?=[_/]|$)")


def fmt(ns):
    if ns is None:
        return "-"
    if ns >= 1e6:
        return f"{ns / 1e6:.2f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f} µs"
    return f"{ns:.0f} ns"


def collect(root):
    rows = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        if "estimates.json" not in filenames or os.path.basename(dirpath) != "new":
            continue
        rel = os.path.relpath(os.path.dirname(dirpath), root).replace(os.sep, "/")
        series = SERIES_RE.findall(rel)
        if len(series) != 1:
            continue
        key = SERIES_RE.sub("", rel).replace("__", "_").replace("_/", "/").replace("/_", "/").replace("//", "/")
        with open(os.path.join(dirpath, "estimates.json")) as f:
            median = json.load(f)["median"]["point_estimate"]
        rows.setdefault(key, {})[series[0]] = median
    return rows


def sort_key(k):
    return [int(p) if p.isdigit() else p for p in k.split("/")]


def print_table(title, rows, series, after, after_label):
    keys = sorted((k for k, r in rows.items() if any(s in r for s in series)), key=sort_key)
    if not keys:
        return
    before = [s for s in series if s != after]
    headers = ("benchmark", *series, *(f"{after_label} vs {s.lower()}" for s in before))
    table = []
    for key in keys:
        r = rows[key]
        speedups = tuple(
            f"{r[s] / r[after]:.2f}x" if r.get(after) and r.get(s) else "-" for s in before
        )
        table.append((key, *(fmt(r.get(s)) for s in series), *speedups))
    widths = [max(len(row[i]) for row in [headers, *table]) for i in range(len(headers))]
    print(f"\n{title}")
    for row in [headers, tuple("-" * w for w in widths), *table]:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)))


def main(root):
    rows = collect(root)
    if not rows:
        print(f"no lincomb results under {root}")
        return
    for title, series, after, after_label in COMPARISONS:
        print_table(title, rows, series, after, after_label)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("target", "criterion"))
