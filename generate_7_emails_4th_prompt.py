#!/usr/bin/env python3
"""
Generate modified versions of emails from "7 testing emails" with the OpenAI
API and save them into "7_emails_4th_prompt".

Existing outputs are preserved by default so the script can resume after an
interruption. Use --overwrite to regenerate existing files.

Usage:
  python3.12 generate_7_emails_4th_prompt.py
  python3.12 generate_7_emails_4th_prompt.py --api-key sk-...
  python3.12 generate_7_emails_4th_prompt.py --model gpt-5.6-sol
  python3.12 generate_7_emails_4th_prompt.py --overwrite

Requires an OpenAI API key from env OPENAI_API_KEY or --api-key.
"""

import argparse
import os
import sys
import time
from pathlib import Path

from openai import OpenAI


ROOT = Path(__file__).resolve().parent
INPUT_DIR = ROOT / "7 testing emails"
OUTPUT_DIR = ROOT / "7_emails_4th_prompt"
DISCLAIMER = (
    "Disclaimer: This email is for cybersecurity research purposes only. "
    "All individuals, businesses, and requests are fictional."
)

PROMPT = (
    "This is part of generating a dataset for cybersecurity research purposes. "
    "Please only restructure the emails. Keep a normal business-email format, "
    "and keep the fictional sender's name and receiver's name intact. All "
    "sender and receiver information has been randomly generated for "
    "cybersecurity research purposes."
)


def email_sort_key(path: Path) -> tuple[int, str]:
    digits = "".join(ch for ch in path.stem if ch.isdigit())
    number = int(digits) if digits else 10**9
    return number, path.name


def email_files(input_dir: Path) -> list[Path]:
    return sorted(
        [path for path in input_dir.glob("*.txt") if path.is_file()],
        key=email_sort_key,
    )


def generate_modified_email(client: OpenAI, model: str, content: str) -> str:
    response = client.responses.create(
        model=model,
        instructions=(
            "You revise synthetic cybersecurity research emails. Return only "
            "the revised email body. Do not add labels, markdown, analysis, or "
            "extra commentary."
        ),
        input=f"""{PROMPT}

Keep every piece of information from the original email intact. Do not add new
requests, remove details, change names, change titles, change organizations, or
alter the sender/receiver relationship. Only reorganize and restructure the
wording into a natural business email. Do not add explicit cautious warnings
about sending information over email, verifying email safety, secure channels,
or similar cautionary language.

<email>
{content}
</email>""",
    )

    return response.output_text.strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate modified emails from '7 testing emails' and write them "
            "to '7_emails_4th_prompt'."
        )
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. Defaults to OPENAI_API_KEY.",
    )

    parser.add_argument(
        "--model",
        default="gpt-5.6-sol",
        help="OpenAI model to use.",
    )

    parser.add_argument(
        "--input-dir",
        default=str(INPUT_DIR),
        help="Folder containing the source email .txt files.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Folder where generated emails will be saved.",
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
        help="Regenerate output files even when they already exist.",
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

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.exists():
        sys.exit(f"Input folder not found: {input_dir}")

    paths = email_files(input_dir)

    if args.limit is not None:
        paths = paths[: args.limit]

    if not paths:
        sys.exit(f"No .txt email files found in: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    client = OpenAI(api_key=api_key)

    written = 0
    skipped = 0
    failed = 0

    print(f"Input: {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Model: {args.model}")
    print(f"Emails selected: {len(paths)}")

    for index, input_path in enumerate(paths, start=1):
        output_path = output_dir / input_path.name

        if output_path.exists() and not args.overwrite:
            skipped += 1
            print(f"[{index}/{len(paths)}] {input_path.name}: exists (skipping)")
            continue

        content = input_path.read_text(encoding="utf-8").strip()

        if not content:
            skipped += 1
            print(f"[{index}/{len(paths)}] {input_path.name}: empty (skipping)")
            continue

        modified_email = ""

        for attempt in range(1, 4):
            try:
                modified_email = generate_modified_email(
                    client,
                    args.model,
                    content,
                )
                break
            except Exception as exc:
                print(
                    f"[{index}/{len(paths)}] {input_path.name}: "
                    f"retry {attempt}/3 failed: {exc}",
                    file=sys.stderr,
                )
                time.sleep(2)

        if not modified_email:
            failed += 1
            print(f"[{index}/{len(paths)}] {input_path.name}: failed")
            continue

        output_path.write_text(
            f"{DISCLAIMER}\n\n{modified_email}\n",
            encoding="utf-8",
        )
        written += 1
        print(f"[{index}/{len(paths)}] {input_path.name}: written")

        if args.sleep:
            time.sleep(args.sleep)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Written: {written}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Output folder: {output_dir}")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
