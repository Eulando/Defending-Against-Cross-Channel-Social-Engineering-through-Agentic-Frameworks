#!/usr/bin/env python3
"""
CrewAI detector for one victim across ind1..ind4.

Default target:
  Every victim name from column 2 of victims_200-399.csv, skipping the header.

The crew has five agents:
  - one manager agent
  - four channel agents, one for each ind folder

Each channel agent is assigned exactly one task and a folder-restricted search
tool. Each channel agent must be used exactly once: minimum one call and maximum
one call per victim. The manager receives the four channel reports and applies
the threshold rule: any score >= 50 makes the final verdict malicious. If every
score is below 50, the manager reviews the combined original email text for
malicious effects.

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
RESULTS_DIR = ROOT / "crewai_prompt2_results"
VICTIM_NAMES_PATH = ROOT / "victims_200-399.csv"
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
    score: int = Field(..., ge=0, le=100, description="Maliciousness score.")
    summary: str = Field(..., description="Summary of requested information.")
    original_text: str = Field(..., description="Full original email text.")


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
        llm=LLM(model=model, temperature=0),
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
            "This channel agent must be called exactly once for this victim: "
            "minimum one call and maximum one call. Complete all assigned work "
            "inside this single call.\n\n"
            f"Use your search_{channel_dir} tool exactly once with victim_name "
            f'"{victim_name}". Search only {channel_dir}.\n\n'
            "For every matching email, report the file name, a ChatGPT-based "
            "maliciousness score from 0 to 100, and a concise summary of the "
            "information requested in the email. Include the full original email "
            "text as original_text for every finding. Score the individual email only; "
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
            "scenario number, or location hint. You must call each of the four "
            "channel agents exactly once for this victim: minimum one call and "
            "maximum one call per channel agent. Do not skip any channel agent, "
            "and do not call any channel agent more than once. After those four "
            "single calls, use their reports for the final decision.\n\n"
            f"Apply this threshold rule: if any matching email score is {threshold} "
            "or above, final_verdict must be malicious and threshold_triggered "
            "must be true.\n\n"
            "If every individual score is below the threshold, review all channel "
            "reports using the full original_text values, not only their summaries. "
            "Evaluate the combined context and requests across all original emails "
            "to decide whether they have malicious social-engineering effects. In "
            "that case, explain the combined-effect reasoning and set "
            "threshold_triggered to false. Be as conservative as possible to "
            "decide whether the combined context is benign or malicious.\n\n"
            "Return the final verdict and include the four channel reports."
        ),
        expected_output=(
            "A valid ManagerReport JSON-compatible object with victim_name, "
            "threshold, final_verdict, threshold_triggered, combined_effect_review, "
            "rationale, and channel_reports. The channel_reports list must contain "
            "exactly four reports: one report each for channels 1, 2, 3, and 4."
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

    if report is not None:
        public_report = report.model_dump(
            exclude={
                "channel_reports": {
                    "__all__": {
                        "findings": {"__all__": {"original_text"}},
                    },
                },
            }
        )
        json_path.write_text(json.dumps(public_report, indent=2) + "\n", encoding="utf-8")
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
        json_path.write_text(raw_output + "\n", encoding="utf-8")

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
