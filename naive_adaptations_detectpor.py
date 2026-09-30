#!/usr/bin/env python3
"""
CrewAI detector for one victim across ind1..ind4.

Default target:
  Every victim name from column 2 of victim_names.csv, skipping the header.

The crew has five agents:
  - one manager agent
  - four channel agents, one for each ind folder

Each channel agent is assigned exactly one task and a folder-restricted search
tool. Each channel agent returns matching original emails only. The manager
combines the four emails, scores the combined context from 0 to 100, and applies
the threshold rule: combined_score >= threshold makes the final verdict
malicious; below threshold makes it benign.

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
RESULTS_DIR = ROOT / "naive_adaptations_findings"
VICTIM_NAMES_PATH = ROOT / "victim_names.csv"
CHANNEL_DIRS = ["ind1", "ind2", "ind3", "ind4"]
DEFAULT_MODEL = "gpt-4o-mini"
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
    channel_email: str = Field(..., description="Original email content.")


class ChannelReport(BaseModel):
    channel: int
    victim_name: str
    findings: list[EmailFinding]
    rationale: str


class ManagerReport(BaseModel):
    victim_name: str
    threshold: int
    combined_score: int = Field(..., ge=0, le=100)
    final_verdict: Literal["benign", "malicious"]
    threshold_triggered: bool
    rationale: str
    channel_reports: list[ChannelReport]


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
            "and deliver each matching original email to the manager without "
            "scoring, verdicts, or summaries."
        ),
        backstory=(
            "You are a cybersecurity analyst assigned to one communication "
            "channel. You do not inspect other channels. Your role is only to "
            "find matching emails and pass their original contents to the manager."
        ),
        tools=[ChannelSearchTool(channel_dir)],
        llm=LLM(model=model, temperature=0),
        allow_delegation=False,
        verbose=verbose,
        max_iter=4,
    )


def build_manager_agent(model: str, verbose: bool) -> Agent:
    return Agent(
        role="Manager Agent",
        goal=(
            "Combine the original emails from the four channel reports for one "
            "victim, score the combined context, and decide whether it is benign "
            "or malicious."
        ),
        backstory=(
            "You manage a multi-channel social-engineering detector. You provide "
            "the victim name to channel analysts, receive their original emails, "
            "combine all channel evidence, assign one combined maliciousness score, "
            "and apply the threshold rule."
        ),
        llm=LLM(model=model, temperature=0),
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
            "For every matching email, report only the file name and the exact "
            "original email content in channel_email. Do not score the email. "
            "Do not provide a channel verdict. Do not summarize the email. Do not "
            "classify it as benign or malicious.\n\n"
            "If you cannot find any email containing the victim name in your "
            'assigned folder, say exactly "cannot be found" in your rationale.\n\n'
            "Return a structured report with the channel number, victim name, "
            "all findings, and a brief rationale."
        ),
        expected_output=(
            "A valid structured ChannelReport. Include every matching file. "
            "Each finding must include filename and channel_email only. No score, "
            "summary, finding verdict, or channel verdict may appear. If there are "
            'no matches, findings must be an empty list and rationale must be "cannot be found".'
        ),
        agent=agent,
        output_pydantic=ChannelReport,
    )


def build_manager_task(
    manager: Agent,
    channel_tasks: list[Task],
    victim_name: str,
    threshold: int,
) -> Task:
    return Task(
        description=(
            f"You are the manager. Provide only this victim name to the channel "
            f"agents: {victim_name}. Do not provide a file name, data subscript, "
            "scenario number, or location hint. You have called each of the four "
            "channel agents exactly once and now have their reports.\n\n"
            "Combine all original channel_email values from the channel reports "
            "into one combined context. Score that combined context on a "
            "maliciousness scale from 0 to 100, where 0 is fully benign and 100 "
            "is fully malicious.\n\n"
            f"Apply this threshold rule exactly: if combined_score is {threshold} "
            "or above, final_verdict must be malicious and threshold_triggered "
            "must be true. If combined_score is below the threshold, final_verdict "
            "must be benign and threshold_triggered must be false.\n\n"
            "Do not use individual channel scores or individual channel verdicts; "
            "the channel agents do not provide them. Return the final verdict, "
            "the combined_score, and the four channel reports."
        ),
        expected_output=(
            "A valid ManagerReport JSON-compatible object with victim_name, "
            "threshold, combined_score, final_verdict, threshold_triggered, "
            "rationale, and channel_reports."
        ),
        agent=manager,
        context=channel_tasks,
        output_pydantic=ManagerReport,
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
    combined_path = RESULTS_DIR / f"crewai_{base}_combined.txt"

    if report is not None:
        json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        combined_parts = []
        rows = []
        for channel_report in report.channel_reports:
            if channel_report.findings:
                for finding in channel_report.findings:
                    combined_parts.append(
                        f"[CHANNEL {channel_report.channel} | {finding.filename}]\n"
                        f"{finding.channel_email}"
                    )
                    rows.append(
                        {
                            "victim_name": report.victim_name,
                            "channel": channel_report.channel,
                            "filename": finding.filename,
                            "channel_email": finding.channel_email,
                            "combined_score": report.combined_score,
                            "final_verdict": report.final_verdict,
                        }
                    )
            else:
                rows.append(
                    {
                        "victim_name": report.victim_name,
                        "channel": channel_report.channel,
                        "filename": "cannot be found",
                        "channel_email": "",
                        "combined_score": report.combined_score,
                        "final_verdict": "N/A",
                    }
                )

        combined_path.write_text("\n\n".join(combined_parts) + "\n", encoding="utf-8")

        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "victim_name",
                    "channel",
                    "filename",
                    "channel_email",
                    "combined_score",
                    "final_verdict",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
    else:
        json_path.write_text(raw_output + "\n", encoding="utf-8")

    print(f"Report: {json_path.name}")
    if report is not None:
        print(f"Findings: {csv_path.name}")
        print(f"Combined emails: {combined_path.name}")


def dry_run(victim_name: str) -> None:
    print(f"\nVictim: {victim_name}")
    for channel_dir in CHANNEL_DIRS:
        matches = find_matches(channel_dir, victim_name)
        print(f"{channel_dir}: {len(matches)} match(es)")
        if not matches:
            print("  cannot be found")
        for match in matches:
            print(f"  {match['filename']}")


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

    channel_tasks = [
        build_channel_task(agent, channel_number, victim_name)
        for channel_number, agent in enumerate(channel_agents, start=1)
    ]
    manager_task = build_manager_task(
        manager,
        channel_tasks,
        victim_name,
        threshold,
    )

    crew = Crew(
        agents=channel_agents,
        tasks=[*channel_tasks, manager_task],
        process=Process.hierarchical,
        manager_agent=manager,
        verbose=verbose,
        tracing=internal_trace,
    )

    result = crew.kickoff()
    report = result.pydantic if isinstance(result.pydantic, ManagerReport) else None
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
            "of victim_names.csv, skipping the header."
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
