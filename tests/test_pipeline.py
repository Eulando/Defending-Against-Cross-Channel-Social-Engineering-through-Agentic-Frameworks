from pathlib import Path

from crosschannel.models import (
    AtomicMessage,
    Channel,
    ExpectedLabel,
    LinkageAudit,
    Mode,
    ScenarioDraft,
    ScoreResult,
)
from crosschannel.pipeline import INDEX_RANGES, Thresholds, run_mode
from crosschannel.storage import RunStore


ELEMENTS = [
    "official project identifier",
    "sponsoring manager name",
    "approved office location",
    "internal support alias",
]


def scenario() -> ScenarioDraft:
    channels = [Channel.EMAIL, Channel.PHONE, Channel.SMS, Channel.DM]
    messages = [
        AtomicMessage(
            channel=channel,
            target_name=f"Fictional Person {position}",
            target_role=f"Department Role {position}",
            atomic_element=ELEMENTS[position - 1],
            body=f"Hello, could you confirm the {ELEMENTS[position - 1]} for Project Cedar? Thanks.",
        )
        for position, channel in enumerate(channels, start=1)
    ]
    combined = "Hello, could you confirm " + ", ".join(ELEMENTS) + " for Project Cedar? Thanks."
    return ScenarioDraft(
        fictional_company="Cedar Example Labs",
        industry="Research",
        approximate_size="about 200 employees",
        attacker_persona="Fictional project coordinator",
        ultimate_target="Project Cedar records",
        messages=messages,
        combined_elements=ELEMENTS,
        combined_body=combined,
        construction_summary="Four atomic requests consolidated without adding an action.",
    )


class FakeProvider:
    def __init__(self, mode: Mode):
        self.mode = mode

    def generate(self, mode, candidate_token):
        return scenario()

    def audit_linkage(self, value):
        return LinkageAudit(
            preserves_all_four_requests=True,
            introduces_new_request=False,
            missing_atomic_elements=[],
            added_requests_or_actions=[],
            rationale="Exact semantic match.",
        )

    def score(self, body):
        is_combined = all(element in body for element in ELEMENTS)
        malicious = self.mode.label == ExpectedLabel.MALICIOUS and is_combined
        value = 90 if malicious else 10
        return ScoreResult(
            maliciousness=value,
            verdict=ExpectedLabel.MALICIOUS if malicious else ExpectedLabel.BENIGN,
            suspicious_signals=[] if not malicious else ["sensitive aggregation"],
            rationale="Deterministic test score.",
        )


class BadLinkageProvider(FakeProvider):
    def audit_linkage(self, value):
        return LinkageAudit(
            preserves_all_four_requests=True,
            introduces_new_request=True,
            missing_atomic_elements=[],
            added_requests_or_actions=["send a temporary password"],
            rationale="Combined introduced a credential request.",
        )

def test_ranges_do_not_overlap():
    values = [set(value) for value in INDEX_RANGES.values()]
    assert sum(len(value) for value in values) == len(set().union(*values))


def test_pipeline_sorts_accepted_malicious(tmp_path: Path):
    mode = Mode.BOTTOM_UP_MALICIOUS
    store = RunStore(tmp_path)
    result = run_mode(FakeProvider(mode), store, mode, 1, 1, Thresholds())
    assert result["accepted"] == 1
    assert (tmp_path / "accepted" / mode.value / "combined" / "data0.txt").exists()
    assert (tmp_path / "scores.csv").exists()
    assert (tmp_path / "manifest.csv").exists()


def test_pipeline_sorts_accepted_benign(tmp_path: Path):
    mode = Mode.BOTTOM_UP_BENIGN
    store = RunStore(tmp_path)
    result = run_mode(FakeProvider(mode), store, mode, 1, 1, Thresholds())
    assert result["accepted"] == 1
    assert (tmp_path / "accepted" / mode.value / "combined" / "data200.txt").exists()


def test_pipeline_rejects_new_combined_action(tmp_path: Path):
    mode = Mode.BOTTOM_UP_MALICIOUS
    store = RunStore(tmp_path)
    result = run_mode(BadLinkageProvider(mode), store, mode, 1, 1, Thresholds())
    assert result["accepted"] == 0
    assert result["rejected_attempts"] == 1
    assert not (tmp_path / "accepted" / mode.value / "combined" / "data0.txt").exists()
    assert (tmp_path / "rejected" / mode.value / "data0_attempt1.json").exists()
