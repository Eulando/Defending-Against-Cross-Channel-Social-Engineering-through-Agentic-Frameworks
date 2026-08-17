#!/usr/bin/env python3
"""Summarize bottom-up success from a scorer CSV."""

import argparse
import csv
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--individual-max", type=int, default=40)
    parser.add_argument("--combined-min", type=int, default=75)
    args = parser.parse_args()

    rows = list(csv.DictReader(args.csv_path.open(encoding="utf-8")))
    complete = []
    for row in rows:
        try:
            scores = [int(row[f"ind{i}"]) for i in range(1, 5)]
            combined = int(row["combined"])
        except (KeyError, TypeError, ValueError):
            continue
        complete.append((row["filename"], scores, combined))

    if not complete:
        raise SystemExit("No complete score rows found")

    low_individual = [r for r in complete if max(r[1]) <= args.individual_max]
    high_combined = [r for r in complete if r[2] >= args.combined_min]
    successful = [
        r for r in complete
        if max(r[1]) <= args.individual_max and r[2] >= args.combined_min
    ]

    total = len(complete)
    pct = lambda n: 100 * n / total
    print(f"Scored scenarios: {total}")
    print(f"All individuals <= {args.individual_max}: "
          f"{len(low_individual)} ({pct(len(low_individual)):.1f}%)")
    print(f"Combined >= {args.combined_min}: "
          f"{len(high_combined)} ({pct(len(high_combined)):.1f}%)")
    print(f"Bottom-up successes: {len(successful)} ({pct(len(successful)):.1f}%)")
    if successful:
        print("Successful IDs: " + ", ".join(r[0] for r in successful))


if __name__ == "__main__":
    main()
