#!/usr/bin/env python3
"""Before/after table of the lincomb benchmarks from criterion's saved estimates.

Usage: lincomb_table.py [target/criterion]

Reads every `new/estimates.json` under the criterion directory whose path contains a backend series
(`Scalar`, `Avx512Ifma`, or `fold` for the previous partial-decryption implementation), groups the series of
one benchmark (same path with the series removed) and prints the median times with the speedups of the IFMA
series over the scalar one and over the fold.
"""
import json
import os
import re
import sys

SERIES = ("fold", "Scalar", "Avx512Ifma")
# Criterion writes group names with their '/' replaced by '_', so a series is a '_'- or '/'-delimited token.
SERIES_RE = re.compile(r"(?<=[_/])(" + "|".join(SERIES) + r")(?=[_/]|$)")


def fmt(ns):
    if ns is None:
        return "-"
    if ns >= 1e6:
        return f"{ns / 1e6:.2f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f} µs"
    return f"{ns:.0f} ns"


def main(root):
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
    if not rows:
        print(f"no lincomb results under {root}")
        return

    def sort_key(k):
        parts = k.split("/")
        return [int(p) if p.isdigit() else p for p in parts]

    headers = ("benchmark", "fold", "Scalar", "Avx512Ifma", "ifma vs scalar", "ifma vs fold")
    table = []
    for key in sorted(rows, key=sort_key):
        r = rows[key]
        ifma, scalar, fold = r.get("Avx512Ifma"), r.get("Scalar"), r.get("fold")
        vs_scalar = f"{scalar / ifma:.2f}x" if ifma and scalar else "-"
        vs_fold = f"{fold / ifma:.2f}x" if ifma and fold else "-"
        table.append((key, fmt(fold), fmt(scalar), fmt(ifma), vs_scalar, vs_fold))
    widths = [max(len(row[i]) for row in [headers, *table]) for i in range(len(headers))]
    for row in [headers, tuple("-" * w for w in widths), *table]:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("target", "criterion"))
