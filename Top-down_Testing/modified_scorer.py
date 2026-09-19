#!/usr/bin/env python3
"""
Scores Top-down_Testing email files with ChatGPT and writes/resumes results in
the local results folder.

Each top-level .txt file in Top-down_Testing is sent to ChatGPT, which returns
a maliciousness score:
  0 = completely benign, 100 = completely malicious.

CSV columns: number, added-content, rephrased, restructured, combined-approach

IMPORTANT:
- If the output CSV already exists, previously scored files are preserved.
- Only missing scores are sent to the API.
- This allows the scorer to resume after interruption and prevents re-scoring
  existing files.

Usage:
  python modified_scorer.py
  python modified_scorer.py --api-key sk-... --model gpt-4o-mini
  python modified_scorer.py --limit 5

Requires an OpenAI API key (env OPENAI_API_KEY or --api-key).
"""

import argparse
import csv
import re
import sys
import time
from pathlib import Path

from openai import OpenAI


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
CATEGORIES = ["added-content", "rephrased", "restructured", "combined-approach"]
OUTPUT_COLUMNS = ["number"] + CATEGORIES

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means completely benign and 100 means completely malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


def file_sort_key(path: Path) -> tuple[int, str]:
    match = re.search(r"data(\d+)", path.name)
    number = int(match.group(1)) if match else 10**9
    return number, path.name


def email_files(root: Path) -> list[Path]:
    return sorted(
        [
            path
            for path in root.glob("*.txt")
            if path.is_file()
        ],
        key=file_sort_key,
    )


def file_info(path: Path) -> tuple[int, str]:
    match = re.fullmatch(
        r"data(\d+)-ind\d+_(added-content|combined-approach|rephrased|restructured)\.txt",
        path.name,
    )
    if not match:
        raise ValueError(
            f"Unexpected file name format: {path.name}. Expected a name like "
            "data229-ind1_added-content.txt"
        )
    return int(match.group(1)), match.group(2)


def read_email(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def score_email(client, model: str, content: str) -> str:
    """Ask ChatGPT for a 0-100 maliciousness score; returns the parsed score."""
    if not content:
        return ""

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": content},
        ],
        temperature=0,
        max_tokens=10,
    )

    answer = resp.choices[0].message.content.strip()
    match = re.search(r"(\d{1,3})", answer)

    if match:
        score = int(match.group(1))
        return str(max(0, min(100, score)))

    return ""


def empty_score_row() -> dict[str, str]:
    return {category: "" for category in CATEGORIES}


def load_existing_scores(path: Path) -> dict[int, dict[str, str]]:
    existing = {}

    if not path.exists():
        return existing

    try:
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames and set(reader.fieldnames) == set(OUTPUT_COLUMNS):
                for row in reader:
                    number = row.get("number", "").strip()
                    if not number:
                        continue

                    existing[int(number)] = {
                        category: row.get(category, "").strip()
                        for category in CATEGORIES
                    }
                return existing

            if reader.fieldnames == ["filename", "score"]:
                for row in reader:
                    filename = row.get("filename", "").strip()
                    score = row.get("score", "").strip()

                    if filename:
                        number, category = file_info(Path(filename))
                        existing.setdefault(number, empty_score_row())[category] = score
                return existing

            if reader.fieldnames != OUTPUT_COLUMNS:
                print(
                    f"Warning: existing CSV has unexpected columns: "
                    f"{reader.fieldnames}",
                    file=sys.stderr,
                )
                print(
                    f"Expected columns: {OUTPUT_COLUMNS}",
                    file=sys.stderr,
                )

    except Exception as exc:
        sys.exit(f"Could not read existing CSV: {exc}")

    return existing


def save_scores(path: Path, scores: dict[int, dict[str, str]], files: list[Path]) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    numbers = sorted({file_info(email_file)[0] for email_file in files})

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(OUTPUT_COLUMNS)

        for number in numbers:
            row_scores = scores.get(number, empty_score_row())
            writer.writerow(
                [number] + [row_scores.get(category, "") for category in CATEGORIES]
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score Top-down_Testing email files with ChatGPT"
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key",
    )

    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="ChatGPT model",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only process the first N files",
    )

    parser.add_argument(
        "--output",
        default="top-down_testing_scores.csv",
        help="Output CSV filename inside the results folder",
    )

    args = parser.parse_args()

    api_key = (
        args.api_key
        or __import__("os").environ.get("OPENAI_API_KEY")
    )

    if not api_key:
        sys.exit(
            "No OpenAI API key. Set OPENAI_API_KEY or pass --api-key."
        )

    client = OpenAI(api_key=api_key)

    files = email_files(ROOT)

    if args.limit:
        files = files[: args.limit]

    if not files:
        sys.exit("No .txt files found in Top-down_Testing.")

    out_path = RESULTS_DIR / args.output
    scores = load_existing_scores(out_path)

    if scores:
        print(
            f"Loaded {len(scores)} existing score(s) from "
            f"{out_path}"
        )

    new_scores = 0
    skipped_files = 0

    for pos, email_file in enumerate(files, start=1):
        filename = email_file.name
        number, category = file_info(email_file)
        scores.setdefault(number, empty_score_row())
        existing_score = scores[number].get(category, "").strip()

        print(f"\n[{pos}/{len(files)}] {filename}")

        if existing_score:
            print(f"  {category}: existing score {existing_score} (skipping)")
            skipped_files += 1
            continue

        content = read_email(email_file)

        if not content:
            print("  no content found (skipping)")
            continue

        score = ""

        for attempt in range(3):
            try:
                score = score_email(
                    client,
                    args.model,
                    content,
                )
                break

            except Exception as exc:
                print(
                    f"  retry {attempt + 1}/3 for "
                    f"{filename}: {exc}",
                    file=sys.stderr,
                )

                time.sleep(2)

        scores[number][category] = score
        new_scores += 1

        print(f"  {category}: {score}")

        save_scores(out_path, scores, files)
        time.sleep(0.25)

    save_scores(out_path, scores, files)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Output: {out_path}")
    print(f"Files processed: {len(files)}")
    print(f"New API scores generated: {new_scores}")
    print(f"Files skipped with existing scores: {skipped_files}")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
