#!/usr/bin/env python3
"""
Extract the malicious tab export from Data Sets into data files.

Expected columns:
  Content, split#1, split#2, split#3, split#4

Outputs:
  combined/data0.txt, combined/data1.txt, ...
  ind1/data0.txt, ind2/data0.txt, ind3/data0.txt, ind4/data0.txt, ...
"""

import argparse
import csv
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUTS = {
    "Content": "combined",
    "split#1": "ind1",
    "split#2": "ind2",
    "split#3": "ind3",
    "split#4": "ind4",
}
HEADER_RE = re.compile(r"^\s*(subject|to|from|date)\s*:", re.IGNORECASE)


def clean_text(value: str) -> str:
    lines = str(value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cleaned = [line for line in lines if not HEADER_RE.match(line)]
    return "\n".join(cleaned).strip() + "\n"


def find_column(fieldnames: list[str], wanted: str) -> str:
    normalized = {name.strip().lower(): name for name in fieldnames}
    key = wanted.lower()
    if key not in normalized:
        raise SystemExit(
            f"Missing required column {wanted!r}. Found columns: {fieldnames}"
        )
    return normalized[key]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Data Sets malicious tab CSV into data*.txt files."
    )
    parser.add_argument("csv_path", type=Path, help="CSV export of the malicious tab")
    parser.add_argument(
        "--start",
        type=int,
        default=0,
        help="Starting data index for output files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files",
    )
    args = parser.parse_args()

    if not args.csv_path.exists():
        sys.exit(f"CSV file does not exist: {args.csv_path}")

    with args.csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            sys.exit("CSV has no header row")

        columns = {
            source: find_column(reader.fieldnames, source)
            for source in OUTPUTS
        }
        rows = list(reader)

    planned = []
    skipped_rows = []
    written_rows = 0
    for row_number, row in enumerate(rows, start=2):
        cleaned_by_source = {
            source: clean_text(row[columns[source]])
            for source in OUTPUTS
        }
        empty_sources = [
            source
            for source, content in cleaned_by_source.items()
            if not content.strip()
        ]
        if empty_sources:
            skipped_rows.append((row_number, empty_sources))
            continue

        idx = args.start + written_rows
        for source, folder in OUTPUTS.items():
            planned.append((ROOT / folder / f"data{idx}.txt", cleaned_by_source[source]))
        written_rows += 1

    if not args.force:
        existing = [path for path, _ in planned if path.exists()]
        if existing:
            sample = "\n".join(str(path) for path in existing[:10])
            sys.exit(
                "Refusing to overwrite existing files without --force. "
                f"First existing paths:\n{sample}"
            )

    for folder in OUTPUTS.values():
        (ROOT / folder).mkdir(exist_ok=True)

    for path, content in planned:
        path.write_text(content, encoding="utf-8")

    print(f"Read {len(rows)} CSV row(s).")
    print(f"Skipped {len(skipped_rows)} row(s) without complete text.")
    if skipped_rows:
        sample = ", ".join(
            f"CSV row {row_number} ({'/'.join(empty_sources)})"
            for row_number, empty_sources in skipped_rows[:10]
        )
        print(f"Skipped row sample: {sample}")
    print(f"Extracted {written_rows} row(s).")
    print(f"Wrote {len(planned)} file(s), starting at data{args.start}.txt.")


if __name__ == "__main__":
    main()
