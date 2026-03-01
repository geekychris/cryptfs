#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compare CryptoFS vs baseline fio benchmark results."""

import json
import os
import sys
from pathlib import Path

RESULTS_DIR = os.environ.get("RESULTS_DIR", "/tmp/cryptofs_results")

TESTS = [
    ("seq_write_4k", "Sequential Write 4K", "write"),
    ("seq_read_4k", "Sequential Read 4K", "read"),
    ("seq_write_1m", "Sequential Write 1M", "write"),
    ("seq_read_1m", "Sequential Read 1M", "read"),
    ("rand_read_4k", "Random Read 4K", "read"),
    ("rand_write_4k", "Random Write 4K", "write"),
    ("rand_rw_4k", "Random R/W 4K", "mixed"),
]


def extract_metrics(filepath, direction):
    """Extract bandwidth, IOPS, and latency from fio JSON output."""
    try:
        with open(filepath) as f:
            data = json.load(f)
        job = data["jobs"][0]

        if direction == "read":
            return {
                "bw_bytes": job["read"]["bw_bytes"],
                "iops": job["read"]["iops"],
                "lat_ns": job["read"]["lat_ns"]["mean"],
            }
        elif direction == "write":
            return {
                "bw_bytes": job["write"]["bw_bytes"],
                "iops": job["write"]["iops"],
                "lat_ns": job["write"]["lat_ns"]["mean"],
            }
        else:  # mixed
            return {
                "bw_bytes": job["read"]["bw_bytes"] + job["write"]["bw_bytes"],
                "iops": job["read"]["iops"] + job["write"]["iops"],
                "lat_ns": job["read"]["lat_ns"]["mean"],
            }
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return None


def format_bw(bw_bytes):
    return f"{bw_bytes / 1048576:.1f} MB/s"


def format_iops(iops):
    return f"{iops:.0f}"


def format_lat(lat_ns):
    return f"{lat_ns / 1000:.1f} µs"


def main():
    results_dir = Path(RESULTS_DIR)

    print("=" * 90)
    print("CryptoFS vs Baseline Performance Comparison")
    print("=" * 90)
    print()
    print(
        f"{'Test':<25} {'Baseline BW':<15} {'CryptoFS BW':<15} "
        f"{'Overhead':<12} {'Base IOPS':<12} {'CF IOPS':<12}"
    )
    print("-" * 90)

    for test_name, label, direction in TESTS:
        baseline = extract_metrics(
            results_dir / f"baseline_{test_name}.json", direction
        )
        cryptofs = extract_metrics(
            results_dir / f"cryptofs_{test_name}.json", direction
        )

        if baseline and cryptofs:
            overhead = (
                (1 - cryptofs["bw_bytes"] / baseline["bw_bytes"]) * 100
                if baseline["bw_bytes"] > 0
                else 0
            )
            print(
                f"{label:<25} {format_bw(baseline['bw_bytes']):<15} "
                f"{format_bw(cryptofs['bw_bytes']):<15} "
                f"{overhead:>+.1f}%{'':>6} "
                f"{format_iops(baseline['iops']):<12} "
                f"{format_iops(cryptofs['iops']):<12}"
            )
        else:
            print(f"{label:<25} {'N/A':<15} {'N/A':<15} {'N/A':<12}")

    print()
    print("Negative overhead = CryptoFS slower than baseline")
    print(f"Target: <15% sequential overhead, <25% random overhead")
    print()
    print(f"Raw results in: {results_dir}")


if __name__ == "__main__":
    main()
