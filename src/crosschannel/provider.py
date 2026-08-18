from __future__ import annotations

from typing import Protocol, TypeVar

from openai import OpenAI
from pydantic import BaseModel

from .models import LinkageAudit, Mode, ScenarioDraft, ScoreResult
from .prompts import (
    LINKAGE_AUDIT_SYSTEM_PROMPT,
    SCORING_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    generation_prompt,
)


T = TypeVar("T", bound=BaseModel)


class Provider(Protocol):
    def generate(self, mode: Mode, candidate_token: str) -> ScenarioDraft: ...
    def score(self, body: str) -> ScoreResult: ...
    def audit_linkage(self, scenario: ScenarioDraft) -> LinkageAudit: ...


class OpenAIProvider:
    """Structured-output adapter for OpenAI's Responses API."""

    def __init__(self, generation_model: str, scoring_model: str, api_key: str | None = None):
        self.client = OpenAI(api_key=api_key)
        self.generation_model = generation_model
        self.scoring_model = scoring_model

    def generate(self, mode: Mode, candidate_token: str) -> ScenarioDraft:
        response = self.client.responses.parse(
            model=self.generation_model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": generation_prompt(mode, candidate_token)},
            ],
            text_format=ScenarioDraft,
        )
        if response.output_parsed is None:
            raise RuntimeError("generation returned no parsed scenario")
        return response.output_parsed

    def score(self, body: str) -> ScoreResult:
        response = self.client.responses.parse(
            model=self.scoring_model,
            input=[
                {"role": "system", "content": SCORING_SYSTEM_PROMPT},
                {"role": "user", "content": body},
            ],
            text_format=ScoreResult,
        )
        if response.output_parsed is None:
            raise RuntimeError("scoring returned no parsed result")
        return response.output_parsed

    def audit_linkage(self, scenario: ScenarioDraft) -> LinkageAudit:
        individual = "\n\n".join(
            f"INDIVIDUAL {position}:\n{message.body}"
            for position, message in enumerate(scenario.messages, start=1)
        )
        content = f"{individual}\n\nCOMBINED:\n{scenario.combined_body}"
        response = self.client.responses.parse(
            model=self.scoring_model,
            input=[
                {"role": "system", "content": LINKAGE_AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": content},
            ],
            text_format=LinkageAudit,
        )
        if response.output_parsed is None:
            raise RuntimeError("linkage audit returned no parsed result")
        return response.output_parsed
