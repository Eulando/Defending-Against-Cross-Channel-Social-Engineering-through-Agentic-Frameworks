#!/usr/bin/env python3
"""Fail when assigned dataset-number ranges overlap."""

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main():
    rows = list(csv.DictReader((ROOT / "dataset_index_ranges.csv").open(encoding="utf-8")))
    claimed = {}
    errors = []
    for row in rows:
        start = int(row["start_index"])
        end = int(row["end_index"])
        if start > end:
            errors.append(f"invalid range: {row['owner']} {start}-{end}")
            continue
        for idx in range(start, end + 1):
            if idx in claimed:
                errors.append(f"data{idx} overlaps: {claimed[idx]} and {row['owner']}")
            claimed[idx] = row["owner"]

    if errors:
        print("\n".join(errors))
        raise SystemExit(1)
    print(f"Validated {len(rows)} non-overlapping ranges covering data0-data{max(claimed)}")


if __name__ == "__main__":
    main()
