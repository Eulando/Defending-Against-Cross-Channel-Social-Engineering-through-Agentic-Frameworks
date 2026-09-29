#!/usr/bin/env python3
"""
CrewAI detector for one victim across ind1..ind4.

Default target:
  Every victim name from column 2 of victims_200-399.csv, skipping the header.

The crew has five agents:
  - one manager agent
  - four channel agents, one for each ind folder

Each channel agent is assigned exactly one task and a folder-restricted search
tool. The manager receives the four channel reports without numeric scores. If
any channel explicitly reports malicious content, the final verdict is
malicious. Otherwise, the manager reviews the combined benign original emails
and summaries for malicious effects.

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
RESULTS_DIR = ROOT / "new_detector_testing"
VICTIM_NAMES_PATH = ROOT / "victims_200-399.csv"
CHANNEL_DIRS = ["ind1", "ind2", "ind3", "ind4"]
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_THRESHOLD = 50
CONSERVATIVE_INSTRUCTION = (
    "Be as conservative as possible when determining if a content is benign or malicious."
)


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
    summary: str = Field(..., description="Summary of requested information.")
    channel_email: str | None = Field(
        default=None,
        description=(
            "Exact email content found and sent by this individual channel agent."
        ),
    )
    finding_verdict: Literal["malicious"] | None = Field(
        default=None,
        description=(
            "Set only when the email is malicious. Leave unset for benign emails."
        ),
    )


class ChannelReport(BaseModel):
    channel: int
    victim_name: str
    findings: list[EmailFinding]
    channel_verdict: Literal["malicious"] | None = Field(
        default=None,
        description="Set only when the channel found malicious content.",
    )
    rationale: str


class ManagerReport(BaseModel):
    victim_name: str
    threshold: int
    combined_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "Manager's combined maliciousness score for original benign email "
            "content. Set after combined review."
        ),
    )
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
            "privately assess each matching email, and summarize the requested "
            f"information. {CONSERVATIVE_INSTRUCTION}"
        ),
        backstory=(
            "You are a cybersecurity analyst assigned to one communication "
            "channel. You do not inspect other channels. You privately assess "
            "only the email content in your assigned folder and report concise "
            f"findings. {CONSERVATIVE_INSTRUCTION}"
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
            f"whether the evidence is benign or malicious. {CONSERVATIVE_INSTRUCTION}"
        ),
        backstory=(
            "You manage a multi-channel social-engineering detector. You provide "
            "the victim name to channel analysts, review their independent "
            "findings, apply the malicious-report rule, and reason about combined "
            "effects only after all channel reports are available. "
            f"{CONSERVATIVE_INSTRUCTION}"
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
            f"{CONSERVATIVE_INSTRUCTION}\n\n"
            "For every matching email, privately determine whether the individual "
            "email is benign or malicious. Do not combine evidence across "
            "channels. Never disclose a numeric score in your final report.\n\n"
            "For every matching email, send the manager the exact email content "
            "from your assigned channel in channel_email, plus the file name and "
            "a concise summary.\n\n"
            "If you determine an email is benign, do not disclose a benign "
            "verdict and do not set finding_verdict for that email.\n\n"
            "If you determine an email is malicious, report the file name, a "
            "concise summary of the requested information, include the exact "
            'channel_email, and set finding_verdict to "malicious". Do not '
            "include a numeric score.\n\n"
            "If you cannot find any email containing the victim name in your "
            'assigned folder, say exactly "cannot be found" in your rationale.\n\n'
            "Return a structured report with the channel number, victim name, "
            "all findings, an optional channel_verdict, and a brief rationale. "
            "Set channel_verdict only when one or more findings are malicious; "
            "leave it unset when all findings are benign."
        ),
        expected_output=(
            "A valid structured ChannelReport. Include every matching file. "
            "No numeric score may appear anywhere in the output. Every finding "
            "must include channel_email containing the exact email from that "
            "channel. Benign findings must not include a verdict. Malicious "
            'findings must set finding_verdict to "malicious". If there are no '
            "matches, findings must be an empty list, channel_verdict must be "
            'unset, and rationale must be "cannot be found".'
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
            f"{CONSERVATIVE_INSTRUCTION}\n\n"
            "The channel agents must not disclose numeric scores to you. Apply "
            'this rule: if any channel report or finding is marked "malicious", '
            "final_verdict must be malicious and threshold_triggered must be true.\n\n"
            "If no individual report is marked malicious, review all channel_email "
            "values and summaries together and decide whether the "
            "combined requests have malicious social-engineering effects. Also "
            "assign your own combined_score from 0 to 100 for the channel emails "
            "considered together. Treat 0 as fully benign and 100 "
            "as fully malicious.\n\n"
            f"If combined_score is {threshold} or above, the score-based decision "
            "is malicious. If combined_score is below the threshold, the "
            "score-based decision is benign. Compare that score-based decision "
            "with your combined-effect assessment. If either decision is "
            "malicious, final_verdict must be malicious. If they disagree, always "
            "use the malicious decision when determining final_verdict and explain "
            "the disagreement in combined_effect_review.\n\n"
            "Set threshold_triggered to true when an individual report is marked "
            "malicious or when combined_score is at or above the threshold. If "
            "the final verdict is malicious only because of your combined-effect "
            "assessment while combined_score is below threshold, set "
            "threshold_triggered to false.\n\n"
            "Return the final verdict and include the four channel reports."
        ),
        expected_output=(
            "A valid ManagerReport JSON-compatible object with victim_name, "
            "threshold, combined_score, final_verdict, threshold_triggered, "
            "combined_effect_review, rationale, and channel_reports."
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
                            "summary": finding.summary,
                            "channel_email": finding.channel_email or "",
                            "finding_verdict": finding.finding_verdict or "",
                            "channel_verdict": channel_report.channel_verdict or "",
                            "final_verdict": report.final_verdict,
                        }
                    )
            else:
                rows.append(
                    {
                        "victim_name": report.victim_name,
                        "channel": channel_report.channel,
                        "filename": "cannot be found",
                        "summary": "cannot be found",
                        "channel_email": "",
                        "finding_verdict": "",
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
                    "summary",
                    "channel_email",
                    "finding_verdict",
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
