from __future__ import annotations

import re

from .models import Mode, ScenarioDraft, normalize


FORBIDDEN_BODY_LABELS = re.compile(
    r"(?im)^\s*(message|channel|from|to|subject|body|verdict|analysis|data extracted)\s*:"
)
FORBIDDEN_META_WORDS = re.compile(r"(?i)\b(classifier|dataset|attack scenario|atomic element)\b")


def validate_scenario(scenario: ScenarioDraft, mode: Mode) -> list[str]:
    errors: list[str] = []
    bodies = [message.body.strip() for message in scenario.messages]
    bodies.append(scenario.combined_body.strip())
    for position, body in enumerate(bodies, start=1):
        if FORBIDDEN_BODY_LABELS.search(body):
            errors.append(f"body {position} contains a metadata header")
        if FORBIDDEN_META_WORDS.search(body):
            errors.append(f"body {position} leaks experiment terminology")

    if len(set(bodies[:4])) != 4:
        errors.append("individual bodies are not distinct")

    combined_lower = normalize(scenario.combined_body)
    for element in scenario.combined_elements:
        keywords = meaningful_words(element)
        if keywords and not enough_overlap(keywords, combined_lower):
            errors.append(f"combined body does not visibly include atomic element: {element}")

    if mode.label.value == "malicious" and not scenario.ultimate_target.strip():
        errors.append("malicious scenario has no ultimate target")
    return errors


def meaningful_words(value: str) -> set[str]:
    stop = {"the", "a", "an", "and", "or", "for", "of", "to", "in", "on", "with"}
    return {word for word in re.findall(r"[a-z0-9]+", value.casefold()) if len(word) > 2 and word not in stop}


def enough_overlap(keywords: set[str], body: str) -> bool:
    present = sum(1 for word in keywords if word in body)
    return present >= max(1, (len(keywords) + 1) // 2)
