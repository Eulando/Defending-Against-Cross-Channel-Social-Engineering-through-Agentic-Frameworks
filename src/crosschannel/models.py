from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class Approach(str, Enum):
    BOTTOM_UP = "bottom_up"
    TOP_DOWN = "top_down"


class ExpectedLabel(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class Mode(str, Enum):
    BOTTOM_UP_MALICIOUS = "bottom_up_malicious"
    TOP_DOWN_MALICIOUS = "top_down_malicious"
    BOTTOM_UP_BENIGN = "bottom_up_benign"
    TOP_DOWN_BENIGN = "top_down_benign"

    @property
    def approach(self) -> Approach:
        return Approach.BOTTOM_UP if self.value.startswith("bottom_up") else Approach.TOP_DOWN

    @property
    def label(self) -> ExpectedLabel:
        return ExpectedLabel.MALICIOUS if self.value.endswith("malicious") else ExpectedLabel.BENIGN


class Channel(str, Enum):
    EMAIL = "email"
    PHONE = "phone_transcript"
    SMS = "sms"
    DM = "dm"


class AtomicMessage(BaseModel):
    channel: Channel
    target_name: str = Field(min_length=2)
    target_role: str = Field(min_length=2)
    atomic_element: str = Field(
        min_length=5,
        description="The exact information or action requested in this message.",
    )
    body: str = Field(
        min_length=20,
        description="Message body only, without labels, analysis, or metadata headers.",
    )


class ScenarioDraft(BaseModel):
    fictional_company: str
    industry: str
    approximate_size: str
    attacker_persona: str
    ultimate_target: str
    messages: list[AtomicMessage] = Field(min_length=4, max_length=4)
    combined_elements: list[str] = Field(min_length=4, max_length=4)
    combined_body: str = Field(min_length=40)
    construction_summary: str

    @model_validator(mode="after")
    def validate_shape(self):
        channels = [message.channel for message in self.messages]
        targets = [message.target_name.casefold() for message in self.messages]
        if len(set(channels)) != 4:
            raise ValueError("the four messages must use four distinct channels")
        if len(set(targets)) != 4:
            raise ValueError("the four messages must target four distinct people")
        atomic = [normalize(message.atomic_element) for message in self.messages]
        combined = [normalize(element) for element in self.combined_elements]
        if atomic != combined:
            raise ValueError("combined_elements must exactly match message atomic_elements in order")
        return self


class ScoreResult(BaseModel):
    maliciousness: int = Field(ge=0, le=100)
    verdict: ExpectedLabel
    suspicious_signals: list[str]
    rationale: str


class ScenarioScores(BaseModel):
    individual: list[ScoreResult] = Field(min_length=4, max_length=4)
    combined: ScoreResult


class LinkageAudit(BaseModel):
    preserves_all_four_requests: bool
    introduces_new_request: bool
    missing_atomic_elements: list[str]
    added_requests_or_actions: list[str]
    rationale: str


def normalize(value: str) -> str:
    return " ".join(value.casefold().split()).strip(" .")
