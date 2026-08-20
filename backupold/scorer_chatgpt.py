#!/usr/bin/env python3

"""
Score the generated email datasets with OpenAI.

For each dataset (dataK.txt), the following five emails are scored:

    ind1/dataK.txt
    ind2/dataK.txt
    ind3/dataK.txt
    ind4/dataK.txt
    combined/dataK.txt

Scores range from:

    0   = completely benign
    100 = completely malicious

Results are:

    1. Printed as a Markdown table in the terminal.
    2. Saved to chatGPT_score.csv.

Examples:

    python scorer_chatgpt.py
    python scorer_chatgpt.py --limit 2
    python scorer_chatgpt.py --limit 10
    python scorer_chatgpt.py --model gpt-4o-mini

The API key is read from:

    OPENAI_API_KEY

Do NOT put your API key directly into this file.
"""

import argparse
import csv
import os
import re
import sys
import time
from pathlib import Path

from openai import OpenAI


# ============================================================================
# CONFIGURATION
# ============================================================================

ROOT = Path(__file__).resolve().parent

SOURCES = [
    "ind1",
    "ind2",
    "ind3",
    "ind4",
    "combined",
]

DEFAULT_MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means completely benign and 100 means completely malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


# ============================================================================
# FIND DATASETS
# ============================================================================

def dataset_ids(root: Path):
    """
    Find dataset numbers from the combined directory.

    For example:

        combined/data0.txt
        combined/data1.txt
        combined/data99.txt

    returns:

        [0, 1, 2, ..., 99]
    """

    combined_dir = root / "combined"

    if not combined_dir.exists():
        return []

    ids = []

    for path in combined_dir.glob("data*.txt"):

        match = re.fullmatch(
            r"data(\d+)",
            path.stem,
        )

        if match:
            ids.append(
                int(match.group(1))
            )

    return sorted(
        set(ids)
    )


# ============================================================================
# READ EMAIL
# ============================================================================

def read_email(root: Path, folder: str, idx: int) -> str:
    """
    Read one email file.

    Returns an empty string if the file does not exist.
    """

    path = (
        root
        / folder
        / f"data{idx}.txt"
    )

    if not path.exists():
        return ""

    return path.read_text(
        encoding="utf-8"
    ).strip()


# ============================================================================
# SCORE EMAIL
# ============================================================================

def score_email(
    client,
    model: str,
    content: str,
) -> str:
    """
    Send one email to OpenAI and return a score from 0 to 100.
    """

    if not content:
        return ""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": content,
            },
        ],
        temperature=0,
        max_tokens=10,
    )

    answer = response.choices[0].message.content

    if not answer:
        return ""

    answer = answer.strip()

    match = re.search(
        r"\b(\d{1,3})\b",
        answer,
    )

    if not match:
        return ""

    score = int(
        match.group(1)
    )

    score = max(
        0,
        min(100, score),
    )

    return str(score)


# ============================================================================
# PRINT TABLE HEADER
# ============================================================================

def print_table_header():
    """
    Print the Markdown table header.
    """

    print()
    print(
        "| **filename** | **ind1** | **ind2** | "
        "**ind3** | **ind4** | **combined** |"
    )

    print(
        "| --- | ---: | ---: | ---: | ---: | ---: |"
    )


# ============================================================================
# PRINT TABLE ROW
# ============================================================================

def print_table_row(
    filename,
    row,
):
    """
    Print one scored dataset as a Markdown table row.
    """

    print(
        f"| {filename} | "
        f"{row[1]} | "
        f"{row[2]} | "
        f"{row[3]} | "
        f"{row[4]} | "
        f"{row[5]} |"
    )


# ============================================================================
# MAIN
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description="Score dataset emails with OpenAI."
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help=(
            "OpenAI API key. "
            "Prefer using OPENAI_API_KEY instead."
        ),
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            f"OpenAI model to use. "
            f"Default: {DEFAULT_MODEL}"
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Only score the first N datasets."
        ),
    )

    parser.add_argument(
        "--output",
        default="chatGPT_score.csv",
        help=(
            "Output CSV filename."
        ),
    )

    args = parser.parse_args()

    # ========================================================================
    # API KEY
    # ========================================================================

    api_key = (
        args.api_key
        or os.environ.get("OPENAI_API_KEY")
    )

    if not api_key:
        sys.exit(
            "No OpenAI API key found.\n"
            "Set OPENAI_API_KEY in your terminal."
        )

    # ========================================================================
    # CREATE CLIENT
    # ========================================================================

    client = OpenAI(
        api_key=api_key
    )

    # ========================================================================
    # FIND DATASETS
    # ========================================================================

    ids = dataset_ids(
        ROOT
    )

    if not ids:
        sys.exit(
            "No datasets found in the combined folder."
        )

    # ========================================================================
    # APPLY LIMIT
    # ========================================================================

    if args.limit is not None:

        if args.limit < 0:
            sys.exit(
                "--limit must be 0 or greater."
            )

        ids = ids[:args.limit]

    if not ids:
        sys.exit(
            "No datasets selected."
        )

    # ========================================================================
    # INFORMATION
    # ========================================================================

    print()
    print(
        f"Found {len(ids)} dataset(s)."
    )

    print(
        f"Model: {args.model}"
    )

    print(
        f"Emails per dataset: {len(SOURCES)}"
    )

    print(
        f"Total emails to score: "
        f"{len(ids) * len(SOURCES)}"
    )

    print()

    # ========================================================================
    # OUTPUT FILE
    # ========================================================================

    out_path = (
        ROOT
        / args.output
    )

    # ========================================================================
    # PRINT TABLE HEADER
    # ========================================================================

    print_table_header()

    # ========================================================================
    # SCORE DATASETS
    # ========================================================================

    with out_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(
            file
        )

        # --------------------------------------------------------------
        # CSV HEADER
        # --------------------------------------------------------------

        writer.writerow(
            [
                "filename",
                "ind1",
                "ind2",
                "ind3",
                "ind4",
                "combined",
            ]
        )

        # --------------------------------------------------------------
        # DATASETS
        # --------------------------------------------------------------

        for position, idx in enumerate(
            ids,
            start=1,
        ):

            filename = (
                f"data{idx}.txt"
            )

            row = [
                filename
            ]

            # ----------------------------------------------------------
            # SCORE THE FIVE EMAILS
            # ----------------------------------------------------------

            for source in SOURCES:

                content = read_email(
                    ROOT,
                    source,
                    idx,
                )

                score = ""

                # ------------------------------------------------------
                # RETRY UP TO 3 TIMES
                # ------------------------------------------------------

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
                            f"\nRetry "
                            f"{attempt + 1}/3 "
                            f"for {filename} "
                            f"({source}): {exc}",
                            file=sys.stderr,
                        )

                        time.sleep(2)

                row.append(
                    score
                )

                # Small pause between API calls.
                time.sleep(0.25)

            # ----------------------------------------------------------
            # WRITE CSV ROW
            # ----------------------------------------------------------

            writer.writerow(
                row
            )

            # Save immediately.
            file.flush()

            # ----------------------------------------------------------
            # PRINT TABLE ROW
            # ----------------------------------------------------------

            print_table_row(
                filename,
                row,
            )

    # ========================================================================
    # FINISHED
    # ========================================================================

    print()
    print(
        "Finished successfully."
    )

    print(
        f"Scores saved to:"
    )

    print(
        out_path
    )


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()