#!/usr/bin/env python3
"""
scorer_chatgpt.py

Scores the synthetic email datasets produced by generate_data.py using
the OpenAI API. This is the ONLY file that touches the API key.

Usage:
    $env:OPENAI_API_KEY="sk-..."      # PowerShell
    python scorer_chatgpt.py                # score all data0..data99
    python scorer_chatgpt.py --limit 1      # score only data0 (testing)
    python scorer_chatgpt.py --limit 5      # score data0..data4

Output:
    chatGPT_score.csv with columns: filename,ind1,ind2,ind3,ind4,combined
    Markdown table rows printed to the terminal as results come in.
"""

import os
import sys
import csv
import time
import argparse

try:
    from openai import OpenAI
except ImportError:
    print("Missing dependency. Install with: pip install openai")
    sys.exit(1)

MODEL = "gpt-4o-mini"

FOLDERS = ["ind1", "ind2", "ind3", "ind4", "combined"]

INDIVIDUAL_SYSTEM_PROMPT = (
    "You are a security-risk evaluator for a synthetic email-security "
    "research dataset. You will be given the text of a single email. "
    "Evaluate ONLY the text you are given - do not assume any outside "
    "context. Judge how much security risk (e.g. social engineering, "
    "information-gathering, pretexting, sensitive-data exposure) this "
    "single email displays on its own. Ordinary administrative "
    "questions are normally low risk. Do not invent facts that are not "
    "in the text. Respond with ONLY an integer from 0 to 100, and "
    "nothing else."
)

COMBINED_SYSTEM_PROMPT = (
    "You are a security-risk evaluator for a synthetic email-security "
    "research dataset. You will be given a 'combined' email that draws "
    "together information from several earlier, separately-sent "
    "emails. Evaluate the actual text you are given. Consider the "
    "relationships among the pieces of information it references, and "
    "determine whether combining that context creates additional "
    "security significance beyond what any single piece would suggest "
    "on its own (for example, easier impersonation, unauthorized "
    "access, or fraud setup). Do not assume malicious intent merely "
    "because several ordinary administrative details are mentioned "
    "together - judge the actual content. Do not invent facts that are "
    "not in the text. Do not default to a fixed or 'typical' score; "
    "base your judgment on this specific email. Respond with ONLY an "
    "integer from 0 to 100, and nothing else."
)


def read_email(base_dir, folder, filename):
    path = os.path.join(base_dir, folder, filename)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def extract_score(raw_text):
    """Pull the first integer 0-100 out of the model's reply."""
    digits = ""
    for ch in raw_text.strip():
        if ch.isdigit():
            digits += ch
        elif digits:
            break
    if not digits:
        raise ValueError(f"Could not parse an integer score from: {raw_text!r}")
    score = int(digits)
    return max(0, min(100, score))


def score_email(client, system_prompt, email_text, retries=3, debug=False):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": email_text},
                ],
                temperature=0,
                max_tokens=20,
            )
            raw = response.choices[0].message.content
            if debug:
                print(f"    [raw model output]: {raw!r}")
            return extract_score(raw)
        except Exception as e:  # noqa: BLE001
            last_err = e
            wait = 2 ** attempt
            print(f"  Attempt {attempt} failed ({e}); retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError(f"Failed to score email after {retries} attempts: {last_err}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100,
                         help="Number of datasets to score, starting at data0 (default: all 100).")
    parser.add_argument("--debug", action="store_true",
                         help="Print the raw model output for each score, "
                              "so you can see the model's actual response "
                              "before it gets parsed into an integer.")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY environment variable is not set.")
        print('PowerShell: $env:OPENAI_API_KEY="your-key-here"')
        sys.exit(1)

    client = OpenAI(api_key=api_key)
    base_dir = os.getcwd()

    limit = max(1, min(100, args.limit))
    filenames = [f"data{i}.txt" for i in range(limit)]

    results = []
    csv_path = os.path.join(base_dir, "chatGPT_score.csv")

    with open(csv_path, "w", newline="", encoding="utf-8") as csv_fh:
        writer = csv.writer(csv_fh)
        writer.writerow(["filename", "ind1", "ind2", "ind3", "ind4", "combined"])

        print("| filename | ind1 | ind2 | ind3 | ind4 | combined |")
        print("|---|---|---|---|---|---|")

        for filename in filenames:
            missing = [f for f in FOLDERS
                       if not os.path.exists(os.path.join(base_dir, f, filename))]
            if missing:
                print(f"Skipping {filename}: missing folders {missing}")
                continue

            if args.debug:
                print(f"\n=== {filename} ===")

            row_scores = {}
            for folder in FOLDERS:
                text = read_email(base_dir, folder, filename)
                prompt = COMBINED_SYSTEM_PROMPT if folder == "combined" else INDIVIDUAL_SYSTEM_PROMPT
                if args.debug:
                    print(f"  [{folder}]")
                score = score_email(client, prompt, text, debug=args.debug)
                row_scores[folder] = score

            writer.writerow([
                filename,
                row_scores["ind1"], row_scores["ind2"],
                row_scores["ind3"], row_scores["ind4"],
                row_scores["combined"],
            ])
            csv_fh.flush()

            print(f"| {filename} | {row_scores['ind1']} | {row_scores['ind2']} | "
                  f"{row_scores['ind3']} | {row_scores['ind4']} | {row_scores['combined']} |")

            results.append((filename, row_scores))

    print(f"\nWrote {len(results)} row(s) to {csv_path}")


if __name__ == "__main__":
    main()