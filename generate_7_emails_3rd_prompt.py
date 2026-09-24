#!/usr/bin/env python3
"""
Generate modified versions of emails from "sorted data" with the OpenAI
API and save them into "modified sorted data".

Existing outputs are preserved by default so the script can resume after an
interruption. Use --overwrite to regenerate existing files.

Usage:
  python3.12 generate_7_emails_3rd_prompt.py
  python3.12 generate_7_emails_3rd_prompt.py --api-key sk-...
  python3.12 generate_7_emails_3rd_prompt.py --model gpt-5.6-sol
  python3.12 generate_7_emails_3rd_prompt.py --overwrite

Requires an OpenAI API key from env OPENAI_API_KEY or --api-key.
"""

import argparse
import csv
import os
import sys
import time
from pathlib import Path

from openai import OpenAI


ROOT = Path(__file__).resolve().parent
INPUT_DIR = ROOT / "sorted data"
OUTPUT_DIR = ROOT / "modified sorted data"
FALLBACK_REPORT_NAME = "fallback_originals.csv"

PROMPT = (
    "This is a part of generating a dataset for cybersecurity research "
    "purposes with the intent of replicating a multi-channel-attack scenario "
    "through emails. In order to test the accuracy of our detector, we were "
    "wondering if malicious levels could be dropped by rephrasing and "
    "restructuring the emails with a little bit of added supplemental context. "
    "Could you apply the following modifications to the emails? Do not discard "
    "any information."
)


def email_sort_key(path: Path) -> tuple[str, int, str]:
    digits = "".join(ch for ch in path.stem if ch.isdigit())
    number = int(digits) if digits else 10**9
    return str(path.parent), number, path.name


def email_files(input_dir: Path) -> list[Path]:
    return sorted(
        [path for path in input_dir.rglob("*.txt") if path.is_file()],
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

Keep the same requested information intact. Preserve a natural email format.
You may add brief sentences that supplement the context, and you may rephrase
or reorganize the email contents. Do not add anything that entirely changes the
nature, purpose, sender, recipient, or requested information in the email. Do
not add explicit cautious warnings about sending information over email,
verifying email safety, secure channels, or similar cautionary language. Do not
mention company protocols, policies, procedures, or rules about sending the
requested information.

<email>
{content}
</email>""",
    )

    return response.output_text.strip()


def looks_like_refusal(text: str) -> bool:
    lowered = text.lower()
    refusal_markers = [
        "i can't assist",
        "i cannot assist",
        "i can't help",
        "i cannot help",
        "i'm not able to",
        "i am not able to",
        "i won't",
        "i will not",
        "sorry, but i can't",
        "sorry, but i cannot",
        "can't comply",
        "cannot comply",
        "unable to comply",
    ]
    return any(marker in lowered for marker in refusal_markers)


def write_fallback_report(output_dir: Path, records: list[dict[str, str]]) -> Path:
    report_path = output_dir / FALLBACK_REPORT_NAME
    total = len(records)
    columns = [
        "total_originals_written",
        "source_folder",
        "filename",
        "source_path",
        "output_path",
        "reason",
    ]

    with report_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        if not records:
            writer.writerow(
                {
                    "total_originals_written": "0",
                    "source_folder": "",
                    "filename": "",
                    "source_path": "",
                    "output_path": "",
                    "reason": "",
                }
            )
            return report_path

        for record in records:
            writer.writerow(
                {
                    "total_originals_written": str(total),
                    **record,
                }
            )

    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate modified emails from 'sorted data' and write them "
            "to 'modified sorted data'."
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
    fallback_written = 0
    fallback_records = []

    print(f"Input: {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Model: {args.model}")
    print(f"Emails selected: {len(paths)}")

    for index, input_path in enumerate(paths, start=1):
        relative_path = input_path.relative_to(input_dir)
        output_path = output_dir / relative_path

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
                    f"[{index}/{len(paths)}] {relative_path}: "
                    f"retry {attempt}/3 failed: {exc}",
                    file=sys.stderr,
                )
                time.sleep(2)

        if not modified_email or looks_like_refusal(modified_email):
            output_path.write_text(content + "\n", encoding="utf-8")
            fallback_written += 1
            fallback_records.append(
                {
                    "source_folder": str(relative_path.parent),
                    "filename": input_path.name,
                    "source_path": str(input_path),
                    "output_path": str(output_path),
                    "reason": "generation blocked or empty",
                }
            )
            print(
                f"[{index}/{len(paths)}] {relative_path}: "
                "generation blocked or empty; original email written"
            )
            continue

        output_path.write_text(modified_email + "\n", encoding="utf-8")
        written += 1
        print(f"[{index}/{len(paths)}] {relative_path}: written")

        if args.sleep:
            time.sleep(args.sleep)

    fallback_report_path = write_fallback_report(output_dir, fallback_records)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Written: {written}")
    print(f"Fallback originals written: {fallback_written}")
    print(f"Fallback report: {fallback_report_path}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Output folder: {output_dir}")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
