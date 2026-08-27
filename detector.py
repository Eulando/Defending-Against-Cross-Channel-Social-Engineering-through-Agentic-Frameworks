#!/usr/bin/env python3
"""
Detect malicious multi-channel scenarios from ind1..ind4.

For each scenario dataK.txt, this script:
  1. Reads ind1/dataK.txt through ind4/dataK.txt.
  2. Sends each channel email individually to ChatGPT for a 0-100
     maliciousness score.
  3. Applies thresholds 25, 50, and 70 to classify each channel as benign or
     malicious.
  4. Marks the final scenario malicious if any individual channel is malicious.
  5. If all four channels are benign, scores the combined information with
     ChatGPT and uses that label as the final decision.
  6. Compares the final decision against chatGPT_score.csv's combined score at
     the same threshold and reports precision, recall, and probability of
     detection.

Raw numeric scores are cached internally, but threshold result files only show
benign/malicious labels.

Outputs:
  detector_channel_scores.csv
  final_result_threshold_25.csv
  final_result_threshold_50.csv
  final_result_threshold_70.csv
  final_result_metrics.csv

Requires an OpenAI API key via OPENAI_API_KEY or --api-key.
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
CHANNEL_DIRS = ["ind1", "ind2", "ind3", "ind4"]
THRESHOLDS = [25, 50, 70]
SCORE_CACHE = "detector_channel_scores.csv"
METRICS_FILE = "final_result_metrics.csv"
REFERENCE_FILE = "chatGPT_score.csv"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in email security. "
    "Rate how malicious the given email content is on a scale from 0 to 100, "
    "where 0 means 100% benign and 100 means 100% malicious. "
    "Consider phishing tactics, urgency, credential requests, impersonation, "
    "suspicious links, secrecy, data aggregation, and social engineering. "
    "Respond with ONLY an integer between 0 and 100 and nothing else."
)


def data_number(filename: str) -> int:
    match = re.fullmatch(r"data(\d+)\.txt", filename)
    return int(match.group(1)) if match else 10**9


def discover_scenarios(start: int | None, end: int | None) -> list[int]:
    common = None

    for directory in CHANNEL_DIRS:
        folder = ROOT / directory
        ids = {
            data_number(path.name)
            for path in folder.glob("data*.txt")
            if data_number(path.name) != 10**9
        }
        common = ids if common is None else common & ids

    scenarios = sorted(common or [])

    if start is not None:
        scenarios = [idx for idx in scenarios if idx >= start]
    if end is not None:
        scenarios = [idx for idx in scenarios if idx <= end]

    return scenarios


def read_email(directory: str, scenario_id: int) -> str:
    path = ROOT / directory / f"data{scenario_id}.txt"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def parse_score(answer: str) -> str:
    match = re.search(r"(\d{1,3})", answer)
    if not match:
        return ""

    score = int(match.group(1))
    return str(max(0, min(100, score)))


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

    return parse_score(response.choices[0].message.content.strip())


def score_with_retries(client: OpenAI, model: str, content: str) -> str:
    for attempt in range(3):
        try:
            return score_email(client, model, content)
        except Exception as exc:
            print(f"    retry {attempt + 1}/3: {exc}", file=sys.stderr)
            time.sleep(2)
    return ""


def load_score_cache(path: Path) -> dict[int, dict[str, str]]:
    if not path.exists():
        return {}

    scores = {}
    expected = [
        "scenario #",
        "channel1_score",
        "channel2_score",
        "channel3_score",
        "channel4_score",
        "combined_score",
    ]
    legacy_expected = expected[:-1]

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames not in (expected, legacy_expected):
            sys.exit(f"{path} has unexpected columns: {reader.fieldnames}")

        for row in reader:
            scenario_id = int(row["scenario #"])
            scores[scenario_id] = {
                "channel1_score": row.get("channel1_score", "").strip(),
                "channel2_score": row.get("channel2_score", "").strip(),
                "channel3_score": row.get("channel3_score", "").strip(),
                "channel4_score": row.get("channel4_score", "").strip(),
                "combined_score": row.get("combined_score", "").strip(),
            }

    return scores


def save_score_cache(path: Path, scores: dict[int, dict[str, str]], scenarios: list[int]) -> None:
    fields = [
        "scenario #",
        "channel1_score",
        "channel2_score",
        "channel3_score",
        "channel4_score",
        "combined_score",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for scenario_id in scenarios:
            row = {"scenario #": scenario_id}
            row.update(scores.get(scenario_id, {}))
            writer.writerow(row)


def is_malicious(score: str, threshold: int) -> bool:
    return bool(score) and int(score) > threshold


def label(score: str, threshold: int) -> str:
    return "malicious" if is_malicious(score, threshold) else "benign"


def write_threshold_results(
    scores: dict[int, dict[str, str]],
    scenarios: list[int],
    threshold: int,
) -> dict[int, str]:
    output = ROOT / f"final_result_threshold_{threshold}.csv"
    final_labels = {}
    fields = ["scenario #", "channel1", "channel2", "channel3", "channel4", "final"]

    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for scenario_id in scenarios:
            row_scores = scores.get(scenario_id, {})
            channels = [
                label(row_scores.get(f"channel{i}_score", ""), threshold)
                for i in range(1, 5)
            ]

            if "malicious" in channels:
                final = "malicious"
            else:
                final = label(row_scores.get("combined_score", ""), threshold)

            final_labels[scenario_id] = final

            writer.writerow(
                {
                    "scenario #": scenario_id,
                    "channel1": channels[0],
                    "channel2": channels[1],
                    "channel3": channels[2],
                    "channel4": channels[3],
                    "final": final,
                }
            )

    return final_labels


def load_combined_reference(path: Path) -> dict[int, str]:
    if not path.exists():
        print(f"Warning: {path} not found. Metrics will be skipped.", file=sys.stderr)
        return {}

    reference = {}

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "filename" not in (reader.fieldnames or []) or "combined" not in (reader.fieldnames or []):
            sys.exit(f"{path} must include filename and combined columns.")

        for row in reader:
            filename = row.get("filename", "").strip()
            combined = row.get("combined", "").strip()
            scenario_id = data_number(filename)

            if scenario_id != 10**9 and combined:
                reference[scenario_id] = combined

    return reference


def combined_review_needed(scores: dict[str, str]) -> bool:
    channel_scores = [scores.get(f"channel{i}_score", "") for i in range(1, 5)]
    if any(not score for score in channel_scores):
        return False

    return any(
        all(not is_malicious(score, threshold) for score in channel_scores)
        for threshold in THRESHOLDS
    )


def combined_content(scenario_id: int) -> str:
    combined = read_email("combined", scenario_id)
    if combined:
        return combined

    parts = []
    for channel_number, directory in enumerate(CHANNEL_DIRS, start=1):
        content = read_email(directory, scenario_id)
        if content:
            parts.append(f"[CHANNEL {channel_number}]\n{content}")

    return "\n\n".join(parts)


def calculate_metrics(predictions: dict[int, str], reference: dict[int, str], threshold: int) -> dict[str, str]:
    tp = fp = tn = fn = skipped = 0

    for scenario_id, predicted in predictions.items():
        combined_score = reference.get(scenario_id, "")
        if not combined_score:
            skipped += 1
            continue

        actual = "malicious" if is_malicious(combined_score, threshold) else "benign"

        if predicted == "malicious" and actual == "malicious":
            tp += 1
        elif predicted == "malicious" and actual == "benign":
            fp += 1
        elif predicted == "benign" and actual == "benign":
            tn += 1
        elif predicted == "benign" and actual == "malicious":
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    return {
        "threshold": str(threshold),
        "tp": str(tp),
        "fp": str(fp),
        "tn": str(tn),
        "fn": str(fn),
        "skipped": str(skipped),
        "precision": f"{precision:.4f}",
        "recall": f"{recall:.4f}",
        "probability_of_detection": f"{recall:.4f}",
    }


def save_metrics(rows: list[dict[str, str]]) -> None:
    fields = [
        "threshold",
        "tp",
        "fp",
        "tn",
        "fn",
        "skipped",
        "precision",
        "recall",
        "probability_of_detection",
    ]

    with (ROOT / METRICS_FILE).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ChatGPT channel detector over ind1-ind4.")
    parser.add_argument("--api-key", default=None, help="OpenAI API key")
    parser.add_argument("--model", default="gpt-4o-mini", help="ChatGPT model")
    parser.add_argument("--start", type=int, default=None, help="First scenario number to process")
    parser.add_argument("--end", type=int, default=None, help="Last scenario number to process")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N scenarios")
    parser.add_argument(
        "--score-cache",
        default=SCORE_CACHE,
        help="CSV file for cached raw channel scores",
    )
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("No OpenAI API key. Set OPENAI_API_KEY or pass --api-key.")

    scenarios = discover_scenarios(args.start, args.end)
    if args.limit is not None:
        scenarios = scenarios[: args.limit]

    if not scenarios:
        sys.exit("No scenarios found across ind1, ind2, ind3, and ind4.")

    cache_path = ROOT / args.score_cache
    scores = load_score_cache(cache_path)
    client = OpenAI(api_key=api_key)

    for pos, scenario_id in enumerate(scenarios, start=1):
        print(f"\n[{pos}/{len(scenarios)}] data{scenario_id}.txt")
        scores.setdefault(scenario_id, {})
        changed = False

        for channel_number, directory in enumerate(CHANNEL_DIRS, start=1):
            key = f"channel{channel_number}_score"

            if scores[scenario_id].get(key, "").strip():
                print(f"  channel{channel_number}: existing internal score")
                continue

            content = read_email(directory, scenario_id)
            if not content:
                print(f"  channel{channel_number}: missing content")
                scores[scenario_id][key] = ""
                continue

            score = score_with_retries(client, args.model, content)
            scores[scenario_id][key] = score
            changed = True
            print(f"  channel{channel_number}: scored internally")
            time.sleep(0.25)

        if combined_review_needed(scores[scenario_id]):
            if scores[scenario_id].get("combined_score", "").strip():
                print("  combined: existing internal score")
            else:
                content = combined_content(scenario_id)
                if content:
                    scores[scenario_id]["combined_score"] = score_with_retries(
                        client,
                        args.model,
                        content,
                    )
                    changed = True
                    print("  combined: scored internally")
                    time.sleep(0.25)
                else:
                    print("  combined: missing content")

        if changed:
            save_score_cache(cache_path, scores, scenarios)

    save_score_cache(cache_path, scores, scenarios)

    reference = load_combined_reference(ROOT / REFERENCE_FILE)
    metric_rows = []

    for threshold in THRESHOLDS:
        predictions = write_threshold_results(scores, scenarios, threshold)
        metric_rows.append(calculate_metrics(predictions, reference, threshold))

    save_metrics(metric_rows)

    print("\nDone.")
    print(f"Raw channel scores: {cache_path}")
    for threshold in THRESHOLDS:
        print(f"Threshold {threshold} results: final_result_threshold_{threshold}.csv")
    print(f"Metrics: {METRICS_FILE}")


if __name__ == "__main__":
    main()
