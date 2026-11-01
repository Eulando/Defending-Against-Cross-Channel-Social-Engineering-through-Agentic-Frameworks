#!/usr/bin/env python3
"""
Scores one named scenario (ind1-ind4 and combined, body text only) with the
project's standard GPT-4o-mini maliciousness judge -- the same system prompt
used to build chatGPT_score.csv. Writes a CSV with one score per channel.

CSV columns: filename, ind1, ind2, ind3, ind4, combined

Usage:
  export OPENAI_API_KEY=sk-...
  python3 score_aero_scenario.py --name aero_example --output aero_scores.csv
"""

import argparse
import csv
import re
import sys
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


def read_email(folder: str, name: str) -> str:
    path = ROOT / folder / f"{name}.txt"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def score_email(client: OpenAI, model: str, content: str) -> int:
    if not content:
        return None
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
    m = re.search(r"(\d{1,3})", answer)
    if not m:
        return None
    return max(0, min(100, int(m.group(1))))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="aero_example", help="base filename, no extension")
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--output", default="aero_scores.csv")
    parser.add_argument("--threshold", type=int, default=50, help="individual-channel benign ceiling")
    parser.add_argument("--combined-threshold", type=int, default=70, help="combined malicious floor")
    args = parser.parse_args()

    api_key = __import__("os").environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("No OpenAI API key. Set OPENAI_API_KEY.")

    client = OpenAI(api_key=api_key)

    scores = {}
    for source in SOURCES:
        content = read_email(source, args.name)
        if not content:
            sys.exit(f"Missing {source}/{args.name}.txt")
        score = score_email(client, args.model, content)
        scores[source] = score
        print(f"{source}: {score}")

    out_path = ROOT / args.output
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["filename"] + SOURCES)
        w.writerow([f"{args.name}.txt"] + [scores[s] for s in SOURCES])
    print(f"\nwrote {out_path}")

    ind_ok = all(scores[s] is not None and scores[s] < args.threshold for s in ("ind1", "ind2", "ind3", "ind4"))
    combined_ok = scores["combined"] is not None and scores["combined"] >= args.combined_threshold
    print(f"\nind1-ind4 all < {args.threshold}: {ind_ok}")
    print(f"combined >= {args.combined_threshold}: {combined_ok}")
    print(f"meets target pattern: {ind_ok and combined_ok}")


if __name__ == "__main__":
    main()
