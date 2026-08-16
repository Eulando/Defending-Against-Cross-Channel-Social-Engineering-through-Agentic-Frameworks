#!/usr/bin/env python3
"""
Scores every email in the dataset with ChatGPT and writes the results to
chatGPT_score.csv.

For each subscription (dataK.txt), the body of ind1, ind2, ind3, ind4 and the
combined folder are each sent to ChatGPT, which returns a maliciousness score:
  0 = completely benign, 100 = completely malicious.

CSV columns: filename, ind1, ind2, ind3, ind4, ind5
(where ind5 holds the score of the combined email).
py
Usage:
  python scorer_chatgpt.py
  python scorer_chatgpt.py --api-key sk-... --model gpt-4o-mini
  python scorer_chatgpt.py --limit 5     # only score the first 5 datasets

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
SOURCES = ["ind1", "ind2", "ind3", "ind4", "combined"]

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means completely benign and 100 means completely malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


def dataset_ids(root: Path) -> list:
    ids = sorted(
        int(p.stem[len("data"):])
        for p in (root / "combined").glob("data*.txt")
    )
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Score dataset emails with ChatGPT")
    parser.add_argument("--api-key", default=None, help="OpenAI API key")
    parser.add_argument("--model", default="gpt-4o-mini", help="ChatGPT model")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only score the first N datasets")
    parser.add_argument("--output", default="chatGPT_score.csv",
                        help="Output CSV path")
    args = parser.parse_args()

    api_key = args.api_key or __import__("os").environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("No OpenAI API key. Set OPENAI_API_KEY or pass --api-key.")

    client = OpenAI(api_key=api_key)

    ids = dataset_ids(ROOT)
    if args.limit:
        ids = ids[: args.limit]

    if not ids:
        sys.exit("No datasets found in the combined folder.")

    out_path = ROOT / args.output
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["filename"] + SOURCES)

        for pos, idx in enumerate(ids, start=1):
            filename = f"data{idx}.txt"
            row = [filename]
            for source in SOURCES:
                content = read_email(ROOT, source, idx)
                score = ""
                for attempt in range(3):
                    try:
                        score = score_email(client, args.model, content)
                        break
                    except Exception as exc:  # transient API errors
                        print(f"  retry {attempt + 1}/3 for {filename} "
                              f"({source}): {exc}", file=sys.stderr)
                        time.sleep(2)
                row.append(score)
                time.sleep(0.25)
            writer.writerow(row)
            f.flush()
            print(f"[{pos}/{len(ids)}] {filename}: {row[1:]}")

    print(f"Done. Scores written to {out_path}")


if __name__ == "__main__":
    main()