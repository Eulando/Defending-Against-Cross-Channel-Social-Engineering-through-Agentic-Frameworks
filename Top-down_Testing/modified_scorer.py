#!/usr/bin/env python3
"""
Scores Top-down_Testing email files with ChatGPT and writes/resumes results in
the local results folder.

Each top-level .txt file in Top-down_Testing is sent to ChatGPT, which returns
a maliciousness score:
  0 = completely benign, 100 = completely malicious.

CSV columns: number, added-content, rephrased, restructured, combined-approach

The sequencial-combination target scores email*.txt files inside
Top-down_Testing/Sequencial Cobination and writes:
  email, score

The add-reconstruct-rephrase target scores email*.txt files inside
Top-down_Testing/Add, Reconstruct, Rephrase and writes:
  email, score

The reconstruct-add target scores email*.txt files inside
Top-down_Testing/Reconstruct, Add and writes:
  email, score

The restructure-add target scores email*.txt files inside
Top-down_Testing/Restructure, Add and writes:
  email, score

The restructure-rephrase target scores email*.txt files inside
Top-down_Testing/Restructure+Rephrase and writes:
  email, score

IMPORTANT:
- If the output CSV already exists, previously scored files are preserved.
- Only missing scores are sent to the API.
- This allows the scorer to resume after interruption and prevents re-scoring
  existing files.

Usage:
  python modified_scorer.py
  python modified_scorer.py --api-key sk-... --model gpt-4o-mini
  python modified_scorer.py --limit 5
  python modified_scorer.py --target sequencial-combination
  python modified_scorer.py --target sequencial-combination --overwrite-existing
  python modified_scorer.py --target add-reconstruct-rephrase
  python modified_scorer.py --target reconstruct-add
  python modified_scorer.py --target restructure-add
  python modified_scorer.py --target restructure-rephrase

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
SEQUENTIAL_DIR = ROOT / "Sequencial Cobination"
ADD_RECONSTRUCT_REPHRASE_DIR = ROOT / "Add, Reconstruct, Rephrase"
RECONSTRUCT_ADD_DIR = ROOT / "Reconstruct, Add"
RESTRUCTURE_ADD_DIR = ROOT / "Restructure, Add"
RESTRUCTURE_REPHRASE_DIR = ROOT / "Restructure+Rephrase"
CATEGORIES = ["added-content", "rephrased", "restructured", "combined-approach"]
OUTPUT_COLUMNS = ["number"] + CATEGORIES
SEQUENTIAL_COLUMNS = ["email", "score"]

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


def sequential_email_sort_key(path: Path) -> tuple[int, str]:
    match = re.fullmatch(r"email(\d+)\.txt", path.name)
    number = int(match.group(1)) if match else 10**9
    return number, path.name


def sequential_email_files(folder: Path) -> list[Path]:
    return sorted(
        [
            path
            for path in folder.glob("email*.txt")
            if path.is_file()
        ],
        key=sequential_email_sort_key,
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


def load_existing_sequential_scores(path: Path) -> dict[str, str]:
    existing = {}

    if not path.exists():
        return existing

    try:
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames != SEQUENTIAL_COLUMNS:
                print(
                    f"Warning: existing CSV has unexpected columns: "
                    f"{reader.fieldnames}",
                    file=sys.stderr,
                )
                print(
                    f"Expected columns: {SEQUENTIAL_COLUMNS}",
                    file=sys.stderr,
                )

            for row in reader:
                email = row.get("email", "").strip()
                score = row.get("score", "").strip()

                if email:
                    existing[email] = score

    except Exception as exc:
        sys.exit(f"Could not read existing CSV: {exc}")

    return existing


def save_sequential_scores(path: Path, scores: dict[str, str], files: list[Path]) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(SEQUENTIAL_COLUMNS)

        for email_file in files:
            writer.writerow([email_file.name, scores.get(email_file.name, "")])


def score_email_folder(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
    folder: Path,
    label: str,
) -> None:
    files = sequential_email_files(folder)

    if limit:
        files = files[:limit]

    if not files:
        sys.exit(f"No email*.txt files found in {folder}.")

    scores = {} if overwrite_existing else load_existing_sequential_scores(out_path)

    if overwrite_existing:
        print(f"Overwriting existing {label} scores.")
    elif scores:
        print(
            f"Loaded {len(scores)} existing score(s) from "
            f"{out_path}"
        )

    new_scores = 0
    skipped_files = 0

    for pos, email_file in enumerate(files, start=1):
        filename = email_file.name
        existing_score = scores.get(filename, "").strip()

        print(f"\n[{pos}/{len(files)}] {filename}")

        if existing_score:
            print(f"  existing score {existing_score} (skipping)")
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
                    model,
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

        scores[filename] = score
        new_scores += 1

        print(f"  score: {score}")

        save_sequential_scores(out_path, scores, files)
        time.sleep(0.25)

    save_sequential_scores(out_path, scores, files)

    print("\n----------------------------------------")
    print("Done.")
    print(f"Output: {out_path}")
    print(f"Files processed: {len(files)}")
    print(f"New API scores generated: {new_scores}")
    print(f"Files skipped with existing scores: {skipped_files}")
    print("----------------------------------------")


def score_sequential_combination(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    score_email_folder(
        client,
        model,
        limit,
        out_path,
        overwrite_existing,
        SEQUENTIAL_DIR,
        "sequential-combination",
    )


def score_add_reconstruct_rephrase(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    score_email_folder(
        client,
        model,
        limit,
        out_path,
        overwrite_existing,
        ADD_RECONSTRUCT_REPHRASE_DIR,
        "add-reconstruct-rephrase",
    )


def score_reconstruct_add(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    score_email_folder(
        client,
        model,
        limit,
        out_path,
        overwrite_existing,
        RECONSTRUCT_ADD_DIR,
        "reconstruct-add",
    )


def score_restructure_add(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    score_email_folder(
        client,
        model,
        limit,
        out_path,
        overwrite_existing,
        RESTRUCTURE_ADD_DIR,
        "restructure-add",
    )


def score_restructure_rephrase(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    score_email_folder(
        client,
        model,
        limit,
        out_path,
        overwrite_existing,
        RESTRUCTURE_REPHRASE_DIR,
        "restructure-rephrase",
    )


def score_top_down_files(
    client: OpenAI,
    model: str,
    limit: int | None,
    out_path: Path,
    overwrite_existing: bool,
) -> None:
    files = email_files(ROOT)

    if limit:
        files = files[:limit]

    if not files:
        sys.exit("No .txt files found in Top-down_Testing.")

    scores = {} if overwrite_existing else load_existing_scores(out_path)

    if overwrite_existing:
        print("Overwriting existing top-down scores.")
    elif scores:
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
                    model,
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
        "--target",
        choices=[
            "top-down",
            "sequencial-combination",
            "add-reconstruct-rephrase",
            "reconstruct-add",
            "restructure-add",
            "restructure-rephrase",
        ],
        default="top-down",
        help="Which Top-down_Testing email set to score",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV filename inside the results folder",
    )

    parser.add_argument(
        "--overwrite-existing",
        action="store_true",
        help="Ignore existing scores and rescore every selected file",
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

    default_outputs = {
        "top-down": "top-down_testing_scores.csv",
        "sequencial-combination": "sequencial_combination_scores.csv",
        "add-reconstruct-rephrase": "add_reconstruct_rephrase_scores.csv",
        "reconstruct-add": "reconstruct_add_scores.csv",
        "restructure-add": "restructure_add_scores.csv",
        "restructure-rephrase": "restructure_rephrase_scores.csv",
    }
    default_output = default_outputs[args.target]
    out_path = RESULTS_DIR / (args.output or default_output)

    if args.target == "sequencial-combination":
        score_sequential_combination(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )
    elif args.target == "add-reconstruct-rephrase":
        score_add_reconstruct_rephrase(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )
    elif args.target == "reconstruct-add":
        score_reconstruct_add(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )
    elif args.target == "restructure-add":
        score_restructure_add(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )
    elif args.target == "restructure-rephrase":
        score_restructure_rephrase(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )
    else:
        score_top_down_files(
            client,
            args.model,
            args.limit,
            out_path,
            args.overwrite_existing,
        )


if __name__ == "__main__":
    main()
