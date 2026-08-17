#!/usr/bin/env python3
"""Validate structure and body-only formatting for a dataset ID range."""

import argparse
import re
from pathlib import Path


FOLDERS = ["ind1", "ind2", "ind3", "ind4", "combined"]
FORBIDDEN = re.compile(
    r"(?im)^\s*(channel|from|to|subject|body|data extracted|"
    r"single-channel verdict|cross-channel role|attack scenario)\s*:"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("start", type=int)
    parser.add_argument("end", type=int)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()

    errors: list[str] = []
    contents: dict[str, str] = {}
    for idx in range(args.start, args.end + 1):
        for folder in FOLDERS:
            path = args.root / folder / f"data{idx}.txt"
            if not path.is_file():
                errors.append(f"missing: {path.relative_to(args.root)}")
                continue
            text = path.read_text(encoding="utf-8").strip()
            contents[f"{folder}/{idx}"] = text
            if not text:
                errors.append(f"empty: {path.relative_to(args.root)}")
            if FORBIDDEN.search(text):
                errors.append(f"metadata/header found: {path.relative_to(args.root)}")

        individual = [contents.get(f"ind{n}/{idx}", "") for n in range(1, 5)]
        if len(set(individual)) != 4:
            errors.append(f"individual messages are not distinct: data{idx}.txt")
        combined = contents.get(f"combined/{idx}", "")
        if combined in individual:
            errors.append(f"combined duplicates an individual: data{idx}.txt")
        if "temporary password" not in combined or "verification code" not in combined:
            errors.append(f"combined payload markers missing: data{idx}.txt")

    if errors:
        print("Validation failed:")
        print("\n".join(f"- {error}" for error in errors))
        raise SystemExit(1)
    count = args.end - args.start + 1
    print(f"Validated {count} scenarios ({count * len(FOLDERS)} files)")


if __name__ == "__main__":
    main()
