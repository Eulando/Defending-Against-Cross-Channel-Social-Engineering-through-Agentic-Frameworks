from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from .models import Mode
from .pipeline import Thresholds, run_mode
from .provider import OpenAIProvider
from .storage import RunStore


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Generate, score, and sort cross-channel datasets")
    root.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    root.add_argument("--generation-model", default=None)
    root.add_argument("--scoring-model", default=None)
    root.add_argument("--allow-same-model", action="store_true")
    sub = root.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="generate, blindly score, and sort one or all modes")
    run.add_argument("--mode", choices=[mode.value for mode in Mode] + ["all"], default="all")
    run.add_argument("--count", type=int, default=10, help="accepted datasets requested per mode")
    run.add_argument("--max-attempts", type=int, default=5)
    run.add_argument("--individual-max", type=int, default=40)
    run.add_argument("--malicious-combined-min", type=int, default=75)
    run.add_argument("--benign-combined-max", type=int, default=40)
    run.add_argument("--sleep", type=float, default=0.0)
    return root


def main() -> None:
    load_dotenv()
    args = parser().parse_args()
    generation_model = args.generation_model or os.getenv("OPENAI_GENERATION_MODEL", "gpt-5-mini")
    scoring_model = args.scoring_model or os.getenv("OPENAI_SCORING_MODEL", "gpt-4.1-mini")
    if generation_model == scoring_model and not args.allow_same_model:
        raise SystemExit("Generation and scoring models must differ (or pass --allow-same-model).")
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set. Copy .env.example to .env and add your key.")

    provider = OpenAIProvider(generation_model, scoring_model)
    store = RunStore(args.artifacts)
    thresholds = Thresholds(
        individual_max=args.individual_max,
        malicious_combined_min=args.malicious_combined_min,
        benign_combined_max=args.benign_combined_max,
    )
    modes = list(Mode) if args.mode == "all" else [Mode(args.mode)]
    results = [
        run_mode(provider, store, mode, args.count, args.max_attempts, thresholds, args.sleep)
        for mode in modes
    ]
    summary = {
        "generation_model": generation_model,
        "scoring_model": scoring_model,
        "thresholds": {
            "individual_max": thresholds.individual_max,
            "malicious_combined_min": thresholds.malicious_combined_min,
            "benign_combined_max": thresholds.benign_combined_max,
        },
        "results": results,
    }
    store.write_summary(summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
