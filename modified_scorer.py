#!/usr/bin/env python3
"""
Scores emails in restructured data/ with ChatGPT and writes/resumes results in
restructured_chatGPT_score.csv.

For each subscription (dataK.txt), the body of ind1, ind2, ind3, and ind4 are
each sent to ChatGPT, which returns a maliciousness score:
  0 = completely benign, 100 = completely malicious.

CSV columns: filename, ind1, ind2, ind3, ind4

IMPORTANT:
- If restructured_chatGPT_score.csv already exists, previous scores are
  preserved.
- Only missing datasets/scores are sent to the API.
- This allows the scorer to resume after interruption and prevents
  re-scoring existing data.

Usage:
  python modified_scorer.py
  python modified_scorer.py --api-key sk-... --model gpt-4o-mini
  python modified_scorer.py --limit 5
  python modified_scorer.py --input-dir "restructured data trial 2" --output restructured_trail2.csv

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
DATA_ROOT = ROOT / "restructured data"
SOURCES = ["ind1", "ind2", "ind3", "ind4"]

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means completely benign and 100 means completely malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


def dataset_ids(root: Path) -> list:
    ids = set()

    for source in SOURCES:
        folder = root / source

        if not folder.exists():
            continue

        for path in folder.glob("data*.txt"):
            number_text = path.stem[len("data"):]

            if number_text.isdigit():
                ids.add(int(number_text))

    ids = sorted(ids)
    return ids


def read_email(root: Path, folder: str, idx: int) -> str:
    path = root / folder / f"data{idx}.txt"
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


def load_existing_scores(path: Path) -> dict:
    """
    Load existing scores from restructured_chatGPT_score.csv.

    Returns:
        {
            "data300.txt": {
                "ind1": "20",
                "ind2": "35",
                "ind3": "10",
                "ind4": "5"
            },
            ...
        }
    """
    existing = {}

    if not path.exists():
        return existing

    try:
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            expected_columns = ["filename"] + SOURCES

            if reader.fieldnames != expected_columns:
                print(
                    f"Warning: existing CSV has unexpected columns: "
                    f"{reader.fieldnames}",
                    file=sys.stderr,
                )
                print(
                    f"Expected columns: {expected_columns}",
                    file=sys.stderr,
                )

            for row in reader:
                filename = row.get("filename", "").strip()

                if filename:
                    existing[filename] = {
                        source: row.get(source, "").strip()
                        for source in SOURCES
                    }

    except Exception as exc:
        sys.exit(f"Could not read existing CSV: {exc}")

    return existing


def save_scores(path: Path, scores: dict, ids: list) -> None:
    """
    Write all current scores to the CSV.

    The output is sorted by dataset number.
    """
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["filename"] + SOURCES)

        for idx in ids:
            filename = f"data{idx}.txt"

            row = [filename]

            for source in SOURCES:
                row.append(scores.get(filename, {}).get(source, ""))

            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score dataset emails with ChatGPT"
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
        help="Only process the first N datasets",
    )

    parser.add_argument(
        "--output",
        default="restructured_chatGPT_score.csv",
        help="Output CSV path",
    )

    parser.add_argument(
        "--input-dir",
        default=str(DATA_ROOT),
        help="Input folder containing ind1-ind4 folders.",
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

    data_root = Path(args.input_dir)

    if not data_root.exists():
        sys.exit(f"Input folder not found: {data_root}")

    # Find all datasets.
    ids = dataset_ids(data_root)

    if args.limit:
        ids = ids[: args.limit]

    if not ids:
        sys.exit(f"No datasets found in {data_root}/ind1-ind4.")

    out_path = ROOT / args.output

    # ---------------------------------------------------------
    # Load existing scores.
    # ---------------------------------------------------------
    scores = load_existing_scores(out_path)

    if scores:
        print(
            f"Loaded {len(scores)} existing dataset(s) from "
            f"{out_path}"
        )

    # ---------------------------------------------------------
    # Score datasets.
    # ---------------------------------------------------------
    new_scores = 0
    skipped_datasets = 0

    for pos, idx in enumerate(ids, start=1):
        filename = f"data{idx}.txt"

        # Make sure the dataset has a dictionary entry.
        if filename not in scores:
            scores[filename] = {
                source: ""
                for source in SOURCES
            }

        row_changed = False

        print(f"\n[{pos}/{len(ids)}] {filename}")

        for source in SOURCES:

            # -------------------------------------------------
            # IMPORTANT:
            # If a score already exists, DO NOT call the API.
            # -------------------------------------------------
            existing_score = scores[filename].get(source, "").strip()

            if existing_score:
                print(
                    f"  {source}: existing score {existing_score} "
                    f"(skipping)"
                )
                continue

            content = read_email(data_root, source, idx)

            if not content:
                print(
                    f"  {source}: no content found (skipping)"
                )
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
                        f"{filename} ({source}): {exc}",
                        file=sys.stderr,
                    )

                    time.sleep(2)

            scores[filename][source] = score
            row_changed = True
            new_scores += 1

            print(f"  {source}: {score}")

            time.sleep(0.25)

        # -----------------------------------------------------
        # Save after every dataset.
        #
        # This means if the program crashes/interruption occurs,
        # scores already completed remain in the CSV.
        # -----------------------------------------------------
        if row_changed:
            save_scores(out_path, scores, ids)

        else:
            skipped_datasets += 1
            print(f"  {filename}: all scores already exist")

    # Final save.
    save_scores(out_path, scores, ids)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Output: {out_path}")
    print(f"Datasets processed: {len(ids)}")
    print(f"New API scores generated: {new_scores}")
    print(f"Datasets completely skipped: {skipped_datasets}")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
