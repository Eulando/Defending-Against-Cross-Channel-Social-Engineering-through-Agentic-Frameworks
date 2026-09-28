#!/usr/bin/env python3
"""
CrewAI detector for one victim across ind1..ind4.

Default target:
  Every victim name from column 2 of victims_200-399.csv, skipping the header.

The crew has five agents:
  - one manager agent
  - four channel agents, one for each ind folder

Each channel agent is assigned exactly one task and a folder-restricted search
tool. The manager receives the four channel reports and applies the threshold
rule: any score >= 50 makes the final verdict malicious. If every score is
below 50, the manager reviews the combined original email content for malicious
effects.

Requires OPENAI_API_KEY in the environment.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from typing import Literal

from crewai import Agent, Crew, LLM, Process, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "crewai_detector2_results"
VICTIM_NAMES_PATH = ROOT / "victims_200-399.csv"
CHANNEL_DIRS = ["ind1", "ind2", "ind3", "ind4"]
DEFAULT_MODEL = "gpt-5.6-sol"
DEFAULT_THRESHOLD = 50


class ChannelSearchInput(BaseModel):
    victim_name: str = Field(..., description="Full victim name to search for.")


class ChannelSearchTool(BaseTool):
    channel_dir: str

    def __init__(self, channel_dir: str):
        super().__init__(
            name=f"search_{channel_dir}",
            description=(
                f"Search only the {channel_dir} folder for emails containing "
                "the supplied full victim name. Returns JSON with filename and "
                "email content for each matching file."
            ),
            args_schema=ChannelSearchInput,
            max_usage_count=1,
            channel_dir=channel_dir,
        )

    def _run(self, victim_name: str) -> str:
        folder = ROOT / self.channel_dir
        matches = []
        pattern = re.compile(rf"(?<![A-Za-z]){re.escape(victim_name)}(?![A-Za-z])")

        for path in sorted(folder.glob("data*.txt"), key=data_number):
            content = path.read_text(encoding="utf-8", errors="ignore")
            if pattern.search(content):
                matches.append(
                    {
                        "filename": path.name,
                        "path": str(path.relative_to(ROOT)),
                        "content": content.strip(),
                    }
                )

        return json.dumps(
            {
                "channel": self.channel_dir,
                "victim_name": victim_name,
                "matches": matches,
            },
            indent=2,
        )


class EmailFinding(BaseModel):
    filename: str = Field(..., description="The data file containing the email.")
    score: int = Field(..., ge=0, le=100, description="Maliciousness score.")
    summary: str = Field(..., description="Summary of requested information.")
    original_text: str = Field("", description="Original email text.")


class ChannelReport(BaseModel):
    channel: int
    victim_name: str
    findings: list[EmailFinding]
    max_score: int = Field(..., ge=0, le=100)
    channel_verdict: Literal["benign", "malicious"]
    rationale: str


class ManagerReport(BaseModel):
    victim_name: str
    threshold: int
    final_verdict: Literal["benign", "malicious"]
    threshold_triggered: bool
    combined_effect_review: str
    rationale: str
    channel_reports: list[ChannelReport]


MANAGER_REPORT_KEYS = {
    "victim_name",
    "threshold",
    "final_verdict",
    "threshold_triggered",
    "combined_effect_review",
    "rationale",
    "channel_reports",
}


def data_number(path: Path) -> int:
    match = re.fullmatch(r"data(\d+)\.txt", path.name)
    return int(match.group(1)) if match else 10**9


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def require_api_key() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("No OPENAI_API_KEY found. Export it before running this script.")


def load_victims() -> list[str]:
    victims = []

    with VICTIM_NAMES_PATH.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2 and row[1].strip():
                victims.append(row[1].strip())

    if victims:
        return victims

    sys.exit(f"No victim name found in column 2 of {VICTIM_NAMES_PATH.name}.")


def find_matches(channel_dir: str, victim_name: str) -> list[dict[str, str]]:
    tool = ChannelSearchTool(channel_dir)
    payload = json.loads(tool._run(victim_name))
    return payload["matches"]


def build_channel_agent(
    channel_number: int,
    model: str,
    verbose: bool,
) -> Agent:
    channel_dir = f"ind{channel_number}"
    return Agent(
        role=f"Channel {channel_number} Email Analyst",
        goal=(
            f"Search {channel_dir} for emails about the manager-provided victim name, "
            "score each matching email from 0 to 100, and summarize the requested "
            "information."
        ),
        backstory=(
            "You are a cybersecurity analyst assigned to one communication "
            "channel. You do not inspect other channels. You score only the email "
            "content in your assigned folder and report concise findings."
        ),
        tools=[ChannelSearchTool(channel_dir)],
        llm=LLM(model=model, api="responses"),
        allow_delegation=False,
        verbose=verbose,
        max_iter=4,
    )


def build_manager_agent(model: str, verbose: bool) -> Agent:
    return Agent(
        role="Manager Agent",
        goal=(
            "Coordinate the four channel reports for one victim and decide "
            "whether the evidence is benign or malicious."
        ),
        backstory=(
            "You manage a multi-channel social-engineering detector. You provide "
            "the victim name to channel analysts, review their independent "
            "findings, apply the threshold rule, and reason about combined effects "
            "only after all channel reports are available."
        ),
        llm=LLM(model=model, api="responses"),
        allow_delegation=False,
        verbose=verbose,
    )


def build_channel_task(agent: Agent, channel_number: int, victim_name: str) -> Task:
    channel_dir = f"ind{channel_number}"
    return Task(
        description=(
            f"The manager has provided only this victim name: {victim_name}\n\n"
            "The manager has not provided a file name, data subscript, scenario "
            "number, or location hint. You must discover any matching file by "
            f"searching only your assigned {channel_dir} folder.\n\n"
            f"Use your search_{channel_dir} tool exactly once with victim_name "
            f'"{victim_name}". Search only {channel_dir}.\n\n'
            "For every matching email, report the file name, a ChatGPT-based "
            "maliciousness score from 0 to 100, and a concise summary of the "
            "information requested in the email. Score the individual email only; "
            "do not combine evidence across channels. Treat 0 as fully benign and "
            "100 as fully malicious.\n\n"
            "If you cannot find any email containing the victim name in your "
            'assigned folder, say exactly "cannot be found" in your rationale.\n\n'
            "Return a structured report with the channel number, victim name, "
            "all findings, the maximum score, a channel verdict using threshold "
            "50, and a brief rationale."
        ),
        expected_output=(
            "A valid structured ChannelReport. Include every matching file. "
            "If there are no matches, findings must be an empty list, max_score "
            'must be 0, channel_verdict must be benign, and rationale must be '
            '"cannot be found".'
        ),
        agent=agent,
    )


def build_manager_task(
    manager: Agent,
    victim_name: str,
    threshold: int,
) -> Task:
    return Task(
        description=(
            f"You are the manager. Coordinate exactly four channel agents for "
            f"this victim name: {victim_name}.\n\n"
            "You must call each channel agent exactly once: Channel 1 Email "
            "Analyst, Channel 2 Email Analyst, Channel 3 Email Analyst, and "
            "Channel 4 Email Analyst. Do not call any channel agent more than "
            "once. Give each channel agent only the victim name. Do not provide "
            "a file name, data subscript, scenario number, or location hint.\n\n"
            "Each channel agent must search only its assigned ind folder with "
            "its search tool exactly once, score each matching email from 0 to "
            "100, and return a ChannelReport with channel, victim_name, "
            "findings, max_score, channel_verdict, and rationale. Each finding "
            "must include filename, score, summary, and original_text.\n\n"
            "After all four channel reports are available, create the final "
            "ManagerReport yourself.\n\n"
            f"Apply this threshold rule: if any matching email score is {threshold} "
            "or above, final_verdict must be malicious and threshold_triggered "
            "must be true.\n\n"
            "If every individual score is below the threshold, review the "
            "original_text fields from all four channel reports together and "
            "decide whether the combined content or combined intent has "
            "malicious social-engineering effects. In that case, explain the "
            "combined-effect reasoning and set threshold_triggered to false. "
            "Be as conservative as possible to decide whether the combined "
            "context is benign or malicious.\n\n"
            "Return only the final ManagerReport as valid JSON. Do not return "
            "markdown, a Python dict literal, a tool call, or commentary. Use "
            "double-quoted JSON keys and values only. The top-level JSON fields "
            "must be exactly victim_name, threshold, final_verdict, "
            "threshold_triggered, combined_effect_review, rationale, and "
            "channel_reports."
        ),
        expected_output=(
            "Valid JSON matching ManagerReport with victim_name, threshold, "
            "final_verdict, threshold_triggered, combined_effect_review, "
            "rationale, and channel_reports. Each channel report must include "
            "findings with filename, score, summary, and original_text."
        ),
    )


def write_outputs(
    report: ManagerReport | None,
    raw_output: str,
    victim_name: str,
) -> None:
    base = slug(victim_name)
    RESULTS_DIR.mkdir(exist_ok=True)
    json_path = RESULTS_DIR / f"crewai_{base}_report.json"
    csv_path = RESULTS_DIR / f"crewai_{base}_findings.csv"

    if report is not None:
        json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        rows = []
        for channel_report in report.channel_reports:
            if channel_report.findings:
                for finding in channel_report.findings:
                    rows.append(
                        {
                            "victim_name": report.victim_name,
                            "channel": channel_report.channel,
                            "filename": finding.filename,
                            "score": finding.score,
                            "summary": finding.summary,
                            "channel_verdict": channel_report.channel_verdict,
                            "final_verdict": report.final_verdict,
                        }
                    )
            else:
                rows.append(
                    {
                        "victim_name": report.victim_name,
                        "channel": channel_report.channel,
                        "filename": "cannot be found",
                        "score": 0,
                        "summary": "cannot be found",
                        "channel_verdict": "N/A",
                        "final_verdict": "N/A",
                    }
                )

        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "victim_name",
                    "channel",
                    "filename",
                    "score",
                    "summary",
                    "channel_verdict",
                    "final_verdict",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
    else:
        fallback = {
            "error": "Manager output could not be parsed as ManagerReport.",
            "victim_name": victim_name,
            "raw_output": raw_output,
        }
        json_path.write_text(json.dumps(fallback, indent=2) + "\n", encoding="utf-8")

    print(f"Report: {json_path.name}")
    if report is not None:
        print(f"Findings: {csv_path.name}")


def dry_run(victim_name: str) -> None:
    print(f"\nVictim: {victim_name}")
    for channel_dir in CHANNEL_DIRS:
        matches = find_matches(channel_dir, victim_name)
        print(f"{channel_dir}: {len(matches)} match(es)")
        if not matches:
            print("  cannot be found")
        for match in matches:
            print(f"  {match['filename']}")


def normalize_manager_candidate(candidate: dict) -> dict:
    for channel_report in candidate.get("channel_reports", []):
        for finding in channel_report.get("findings", []):
            if "summary" not in finding:
                original_text = finding.get("original_text", "")
                finding["summary"] = original_text[:240]
            finding.setdefault("original_text", "")
    return candidate


def parse_manager_report(raw_output: str) -> ManagerReport | None:
    decoder = json.JSONDecoder()

    for pos, char in enumerate(raw_output):
        if char != "{":
            continue

        try:
            candidate, _ = decoder.raw_decode(raw_output[pos:])
        except json.JSONDecodeError:
            continue

        if not isinstance(candidate, dict):
            continue
        if not MANAGER_REPORT_KEYS.issubset(candidate):
            continue

        try:
            return ManagerReport.model_validate(normalize_manager_candidate(candidate))
        except ValueError:
            continue

    return None


def run_detector(
    victim_name: str,
    model: str,
    threshold: int,
    verbose: bool,
    internal_trace: bool,
) -> None:
    print(f"\nProcessing victim: {victim_name}")

    channel_agents = [
        build_channel_agent(
            channel_number,
            model,
            verbose,
        )
        for channel_number in range(1, 5)
    ]
    manager = build_manager_agent(model, verbose)

    manager_task = build_manager_task(
        manager,
        victim_name,
        threshold,
    )

    crew = Crew(
        agents=channel_agents,
        tasks=[manager_task],
        process=Process.hierarchical,
        manager_agent=manager,
        verbose=verbose,
        tracing=internal_trace,
    )

    result = crew.kickoff()
    report = parse_manager_report(result.raw)
    write_outputs(report, result.raw, victim_name)

    if report is not None:
        print(f"Final verdict: {report.final_verdict}")
        print(f"Threshold triggered: {report.threshold_triggered}")
        for channel_report in report.channel_reports:
            if not channel_report.findings:
                print(f"channel{channel_report.channel}: cannot be found")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a CrewAI detector across ind1-ind4."
    )
    parser.add_argument(
        "--victim",
        help=(
            "Full victim name. If omitted, processes every value in column 2 "
            "of victims_200-399.csv, skipping the header."
        ),
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="ChatGPT model")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--verbose", action="store_true", help="Enable CrewAI logs")
    parser.add_argument(
        "--internal-trace",
        action="store_true",
        help=(
            "Enable CrewAI native tracing and verbose terminal logs without "
            "writing trace files."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show matching files without calling ChatGPT.",
    )
    args = parser.parse_args()
    victim_names = [args.victim] if args.victim else load_victims()

    if args.dry_run:
        for victim_name in victim_names:
            dry_run(victim_name)
        return

    require_api_key()
    verbose = args.verbose or args.internal_trace

    for pos, victim_name in enumerate(victim_names, start=1):
        print(f"\n=== Victim {pos}/{len(victim_names)} ===")
        run_detector(
            victim_name=victim_name,
            model=args.model,
            threshold=args.threshold,
            verbose=verbose,
            internal_trace=args.internal_trace,
        )


if __name__ == "__main__":
    main()
