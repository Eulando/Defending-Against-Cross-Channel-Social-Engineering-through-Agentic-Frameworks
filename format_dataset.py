#!/usr/bin/env python3
"""
Splits generated scenario files (output/scenario_NNN.md) into the
ind1..ind4 / combined directory layout specified for the shared dataset.

Aiden's (Gemini) assignment: data10.txt .. data19.txt

ind1/dataN.txt .. ind4/dataN.txt each contain only the raw message
(channel/from/to/subject/body) for that position in the chain, with no
analysis labels, so they can be fed to a single-channel classifier blind.
combined/dataN.txt contains the full scenario including the per-message
labels and the cross-channel correlation analysis, as ground truth.
"""

import re
import sys
from pathlib import Path

SRC_DIR = Path("output")
DEST_ROOT = Path(".")
START_INDEX = 10  # Aiden: data10 - data19
DIRS = ["ind1", "ind2", "ind3", "ind4", "combined"]

MSG_RE = re.compile(r"(?im)^.*\bMESSAGE\s*([1-4])\b.*$")
DATA_EXTRACTED_RE = re.compile(r"(?im)^.*DATA EXTRACTED.*$")


def extract_message(text: str, n: int) -> str:
    matches = list(MSG_RE.finditer(text))
    start_match = next((m for m in matches if m.group(1) == str(n)), None)
    if start_match is None:
        raise ValueError(f"MESSAGE {n} marker not found")
    start = start_match.end()
    end_match = DATA_EXTRACTED_RE.search(text, start)
    end = end_match.start() if end_match else len(text)
    return text[start:end].strip()


def main():
    scenario_files = sorted(SRC_DIR.glob("scenario_*.md"))
    if not scenario_files:
        sys.exit(f"No scenario files found in {SRC_DIR}")

    for d in DIRS:
        (DEST_ROOT / d).mkdir(parents=True, exist_ok=True)

    for i, src in enumerate(scenario_files):
        idx = START_INDEX + i
        text = src.read_text()

        for n in range(1, 5):
            block = extract_message(text, n)
            dest = DEST_ROOT / f"ind{n}" / f"data{idx}.txt"
            dest.write_text(block + "\n")

        dest = DEST_ROOT / "combined" / f"data{idx}.txt"
        dest.write_text(text)

        print(f"{src.name} -> data{idx}.txt (ind1-ind4, combined)")


if __name__ == "__main__":
    main()
