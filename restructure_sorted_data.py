#!/usr/bin/env python3
"""
Restructure emails from sorted data/ with the OpenAI API.

Outputs are written to restructured data/ using the same folder and filename
layout as the input:

  sorted data/ind1/data200.txt
  restructured data/ind1/data200.txt

Existing output files are preserved by default so the script can resume after an
interruption. Use --overwrite to regenerate existing files.

Usage:
  python3 restructure_sorted_data.py
  python3 restructure_sorted_data.py --api-key sk-... --model "gpt5.6 sol"
  python3 restructure_sorted_data.py --limit 10
  python3 restructure_sorted_data.py --overwrite

Requires an OpenAI API key from env OPENAI_API_KEY or --api-key.
"""

import argparse
import os
import sys
import time
from pathlib import Path

from openai import OpenAI


ROOT = Path(__file__).resolve().parent
INPUT_ROOT = ROOT / "sorted data"
OUTPUT_ROOT = ROOT / "restructured data"
SOURCES = ["ind1", "ind2", "ind3", "ind4"]

SYSTEM_PROMPT = """
I am working on generating a dataset for cybersecurity for cross channel social
engineering attacks. As a basic framework, generated malicious data were scored
using open ai api keys, however we were wondering if maliciousness could be
affected by adding sentences and/or rephrasing the sentence structure while
keeping the original information intact.
"""


def sorted_email_paths(input_root: Path, sources: list[str]) -> list[Path]:
    paths = []

    for source in sources:
        folder = input_root / source

        if not folder.exists():
            continue

        paths.extend(folder.glob("data*.txt"))

    def sort_key(path: Path) -> tuple[str, int, str]:
        stem = path.stem
        number_text = stem.removeprefix("data")
        number = int(number_text) if number_text.isdigit() else 999999999
        return path.parent.name, number, path.name

    return sorted(paths, key=sort_key)


def restructure_email(client: OpenAI, model: str, content: str) -> str:
    response = client.responses.create(
        model=model,
        instructions=SYSTEM_PROMPT,
        input=f"""Restructure the following email according to the system instructions.

<email>
{content}
</email>""",
    )

    return response.output_text.strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Restructure emails in sorted data/ with the OpenAI API."
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. Defaults to OPENAI_API_KEY.",
    )

    parser.add_argument(
        "--model",
        default="gpt5.6 sol",
        help="OpenAI model to use.",
    )

    parser.add_argument(
        "--input-dir",
        default=str(INPUT_ROOT),
        help="Input folder containing ind1-ind4 folders.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_ROOT),
        help="Output folder for restructured emails.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only process the first N emails after sorting.",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate files even when output already exists.",
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=0.25,
        help="Seconds to wait between successful API calls.",
    )

    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")

    if not api_key:
        sys.exit("No OpenAI API key. Set OPENAI_API_KEY or pass --api-key.")

    input_root = Path(args.input_dir)
    output_root = Path(args.output_dir)

    if not input_root.exists():
        sys.exit(f"Input folder not found: {input_root}")

    paths = sorted_email_paths(input_root, SOURCES)

    if args.limit is not None:
        paths = paths[: args.limit]

    if not paths:
        sys.exit(f"No data*.txt files found under: {input_root}")

    client = OpenAI(api_key=api_key)

    created = 0
    skipped = 0
    failed = 0

    print(f"Input: {input_root}")
    print(f"Output: {output_root}")
    print(f"Emails selected: {len(paths)}")

    for index, input_path in enumerate(paths, start=1):
        relative_path = input_path.relative_to(input_root)
        output_path = output_root / relative_path

        if output_path.exists() and not args.overwrite:
            skipped += 1
            print(f"[{index}/{len(paths)}] {relative_path}: exists (skipping)")
            continue

        content = input_path.read_text(encoding="utf-8").strip()

        if not content:
            skipped += 1
            print(f"[{index}/{len(paths)}] {relative_path}: empty (skipping)")
            continue

        output_path.parent.mkdir(parents=True, exist_ok=True)

        restructured = ""

        for attempt in range(1, 4):
            try:
                restructured = restructure_email(client, args.model, content)
                break
            except Exception as exc:
                print(
                    f"[{index}/{len(paths)}] {relative_path}: "
                    f"retry {attempt}/3 failed: {exc}",
                    file=sys.stderr,
                )
                time.sleep(2)

        if not restructured:
            failed += 1
            print(f"[{index}/{len(paths)}] {relative_path}: failed")
            continue

        output_path.write_text(restructured + "\n", encoding="utf-8")
        created += 1
        print(f"[{index}/{len(paths)}] {relative_path}: written")

        if args.sleep:
            time.sleep(args.sleep)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Written: {created}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Output folder: {output_root}")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
