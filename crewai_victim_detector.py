#!/usr/bin/env python3
"""
CrewAI detector for one victim across ind1..ind4.

Default target:
  Anton Chekhov

The crew has five agents:
  - one manager agent
  - four channel agents, one for each ind folder

Each channel agent is assigned exactly one task and a folder-restricted search
tool. The manager receives the four channel reports and applies the threshold
rule: any score >= 50 makes the final verdict malicious. If every score is
below 50, the manager reviews the combined summaries for malicious effects.

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
CHANNEL_DIRS = ["ind1", "ind2", "ind3", "ind4"]
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_THRESHOLD = 50
DEFAULT_VICTIM = "Anton Chekhov"


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


def find_matches(channel_dir: str, victim_name: str) -> list[dict[str, str]]:
    tool = ChannelSearchTool(channel_dir)
    payload = json.loads(tool._run(victim_name))
    return payload["matches"]


def build_channel_agent(channel_number: int, model: str, verbose: bool) -> Agent:
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
            f"Apply this threshold rule: if any matching email score is {threshold} "
            "or above, final_verdict must be malicious and threshold_triggered "
            "must be true.\n\n"
            "If every individual score is below the threshold, review all channel "
            "summaries together and decide whether the combined requests have "
            "malicious social-engineering effects. In that case, explain the "
            "combined-effect reasoning and set threshold_triggered to false.\n\n"
            "Return the final verdict and include the four channel reports."
        ),
        expected_output=(
            "A valid ManagerReport JSON-compatible object with victim_name, "
            "threshold, final_verdict, threshold_triggered, combined_effect_review, "
            "rationale, and channel_reports."
        ),
        agent=manager,
        context=channel_tasks,
        output_pydantic=ManagerReport,
    )


def write_outputs(report: ManagerReport | None, raw_output: str, victim_name: str) -> None:
    base = slug(victim_name)
    json_path = ROOT / f"crewai_{base}_report.json"
    csv_path = ROOT / f"crewai_{base}_findings.csv"

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
        json_path.write_text(raw_output + "\n", encoding="utf-8")

    print(f"Report: {json_path.name}")
    if report is not None:
        print(f"Findings: {csv_path.name}")


def dry_run(victim_name: str) -> None:
    for channel_dir in CHANNEL_DIRS:
        matches = find_matches(channel_dir, victim_name)
        print(f"{channel_dir}: {len(matches)} match(es)")
        if not matches:
            print("  cannot be found")
        for match in matches:
            print(f"  {match['filename']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a CrewAI detector for one victim across ind1-ind4."
    )
    parser.add_argument("--victim", default=DEFAULT_VICTIM, help="Full victim name")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="ChatGPT model")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--verbose", action="store_true", help="Enable CrewAI logs")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show matching files without calling ChatGPT.",
    )
    args = parser.parse_args()

    if args.dry_run:
        dry_run(args.victim)
        return

    require_api_key()

    channel_agents = [
        build_channel_agent(channel_number, args.model, args.verbose)
        for channel_number in range(1, 5)
    ]
    manager = build_manager_agent(args.model, args.verbose)

    channel_tasks = [
        build_channel_task(agent, channel_number, args.victim)
        for channel_number, agent in enumerate(channel_agents, start=1)
    ]
    manager_task = build_manager_task(
        manager,
        channel_tasks,
        args.victim,
        args.threshold,
    )

    crew = Crew(
        agents=[manager, *channel_agents],
        tasks=[*channel_tasks, manager_task],
        process=Process.sequential,
        verbose=args.verbose,
    )

    result = crew.kickoff()
    report = result.pydantic if isinstance(result.pydantic, ManagerReport) else None
    write_outputs(report, result.raw, args.victim)

    if report is not None:
        print(f"Final verdict: {report.final_verdict}")
        print(f"Threshold triggered: {report.threshold_triggered}")
        for channel_report in report.channel_reports:
            if not channel_report.findings:
                print(f"channel{channel_report.channel}: cannot be found")


if __name__ == "__main__":
    main()
