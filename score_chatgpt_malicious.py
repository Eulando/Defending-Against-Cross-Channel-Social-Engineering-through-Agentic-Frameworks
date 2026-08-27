#!/usr/bin/env python3
"""
Score the 400-499 multi-channel social-engineering dataset with ChatGPT.

For each subscription dataK.txt, this reads the email bodies from:
  ind1, ind2, ind3, ind4, combined

Each email is sent to ChatGPT for a maliciousness score from 0 to 100:
  0   = 100% benign
  100 = 100% malicious

Results are written to result.csv using the same format as chatGPT_score.csv:
  filename,ind1,ind2,ind3,ind4,combined

Usage:
  python3 score_chatgpt_malicious.py
  python3 score_chatgpt_malicious.py --api-key sk-... --model gpt-4o-mini
  python3 score_chatgpt_malicious.py --limit 5
  python3 score_chatgpt_malicious.py --resume
"""

import argparse
import csv
import os
import re
import sys
import time
from pathlib import Path

from openai import OpenAI

ROOT = Path(__file__).resolve().parent
SOURCES = ["ind1", "ind2", "ind3", "ind4", "combined"]
START_INDEX = 400
END_INDEX = 499

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means 100% benign and 100 means 100% malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, secrecy, data aggregation, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


def dataset_ids() -> list[int]:
    return list(range(START_INDEX, END_INDEX + 1))


def read_email(folder: str, idx: int) -> str:
    path = ROOT / folder / f"data{idx}.txt"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def score_email(client: OpenAI, model: str, content: str) -> str:
    if not content:
        return ""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": content},
        ],
        temperature=0,
        max_tokens=10,
    )

    answer = response.choices[0].message.content.strip()
    match = re.search(r"(\d{1,3})", answer)
    if not match:
        return ""

    score = int(match.group(1))
    return str(max(0, min(100, score)))


def load_existing_scores(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    scores = {}
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        expected_columns = ["filename"] + SOURCES

        if reader.fieldnames != expected_columns:
            sys.exit(
                f"{path} has unexpected columns: {reader.fieldnames}. "
                f"Expected: {expected_columns}"
            )

        for row in reader:
            filename = row.get("filename", "").strip()
            if filename:
                scores[filename] = {
                    source: row.get(source, "").strip()
                    for source in SOURCES
                }

    return scores


def save_scores(path: Path, scores: dict[str, dict[str, str]], ids: list[int]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["filename"] + SOURCES)

        for idx in ids:
            filename = f"data{idx}.txt"
            row = [filename]
            row.extend(scores.get(filename, {}).get(source, "") for source in SOURCES)
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score data400-data499 emails with ChatGPT."
    )
    parser.add_argument("--api-key", default=None, help="OpenAI API key")
    parser.add_argument("--model", default="gpt-4o-mini", help="ChatGPT model")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only score the first N datasets from the 400-499 range",
    )
    parser.add_argument(
        "--output",
        default="result.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Reuse existing scores in the output CSV instead of overwriting them",
    )
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("No OpenAI API key. Set OPENAI_API_KEY or pass --api-key.")

    ids = dataset_ids()
    if args.limit is not None:
        ids = ids[: args.limit]

    output_path = ROOT / args.output
    scores = load_existing_scores(output_path) if args.resume else {}
    client = OpenAI(api_key=api_key)

    for idx in ids:
        filename = f"data{idx}.txt"
        scores.setdefault(filename, {source: "" for source in SOURCES})

    save_scores(output_path, scores, ids)

    new_scores = 0
    for pos, idx in enumerate(ids, start=1):
        filename = f"data{idx}.txt"
        row_changed = False

        print(f"\n[{pos}/{len(ids)}] {filename}")

        for source in SOURCES:
            if scores[filename].get(source, "").strip():
                print(f"  {source}: existing score {scores[filename][source]}")
                continue

            content = read_email(source, idx)
            if not content:
                print(f"  {source}: missing file or empty content")
                continue

            score = ""
            for attempt in range(3):
                try:
                    score = score_email(client, args.model, content)
                    break
                except Exception as exc:
                    print(
                        f"  retry {attempt + 1}/3 for {filename} "
                        f"({source}): {exc}",
                        file=sys.stderr,
                    )
                    time.sleep(2)

            scores[filename][source] = score
            row_changed = True
            new_scores += 1
            print(f"  {source}: {score}")
            time.sleep(0.25)

        if row_changed:
            save_scores(output_path, scores, ids)

    save_scores(output_path, scores, ids)
    print(f"\nDone. Scores written to {output_path}")
    print(f"Datasets: {len(ids)}")
    print(f"New API scores generated: {new_scores}")


if __name__ == "__main__":
    main()
