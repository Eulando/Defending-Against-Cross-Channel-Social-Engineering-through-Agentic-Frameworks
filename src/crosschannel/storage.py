from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import LinkageAudit, Mode, ScenarioDraft, ScenarioScores


FOLDERS = ["ind1", "ind2", "ind3", "ind4", "combined"]


class RunStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save_candidate(self, mode: Mode, idx: int, attempt: int, scenario: ScenarioDraft) -> Path:
        path = self.root / "candidates" / mode.value / f"data{idx}_attempt{attempt}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(scenario.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return path

    def save_rejected(
        self, mode: Mode, idx: int, attempt: int, scenario: ScenarioDraft,
        scores: ScenarioScores | None, reasons: list[str], audit: LinkageAudit | None = None,
    ) -> Path:
        path = self.root / "rejected" / mode.value / f"data{idx}_attempt{attempt}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "mode": mode.value,
            "dataset_index": idx,
            "attempt": attempt,
            "reasons": reasons,
            "scenario": scenario.model_dump(mode="json"),
            "scores": scores.model_dump(mode="json") if scores else None,
            "linkage_audit": audit.model_dump(mode="json") if audit else None,
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def save_accepted(
        self, mode: Mode, idx: int, scenario: ScenarioDraft,
        scores: ScenarioScores, audit: LinkageAudit,
    ):
        base = self.root / "accepted" / mode.value
        for position, message in enumerate(scenario.messages, start=1):
            path = base / f"ind{position}" / f"data{idx}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(message.body.strip() + "\n", encoding="utf-8")
        combined = base / "combined" / f"data{idx}.txt"
        combined.parent.mkdir(parents=True, exist_ok=True)
        combined.write_text(scenario.combined_body.strip() + "\n", encoding="utf-8")

        record = {
            "mode": mode.value,
            "dataset_index": idx,
            "scenario": scenario.model_dump(mode="json"),
            "scores": scores.model_dump(mode="json"),
            "linkage_audit": audit.model_dump(mode="json"),
        }
        metadata = base / "metadata" / f"data{idx}.json"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        self._append_score(mode, idx, scores)
        self._append_manifest(mode, idx)

    def accepted_exists(self, mode: Mode, idx: int) -> bool:
        return (self.root / "accepted" / mode.value / "combined" / f"data{idx}.txt").exists()

    def write_summary(self, payload: dict) -> Path:
        path = self.root / "summary.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def _append_score(self, mode: Mode, idx: int, scores: ScenarioScores):
        path = self.root / "scores.csv"
        row = [mode.value, idx]
        row.extend(score.maliciousness for score in scores.individual)
        row.append(scores.combined.maliciousness)
        self._append_csv(path, ["mode", "dataset_index", "ind1", "ind2", "ind3", "ind4", "combined"], row)

    def _append_manifest(self, mode: Mode, idx: int):
        path = self.root / "manifest.csv"
        prefix = f"accepted/{mode.value}"
        row = [mode.value, idx]
        row.extend(f"{prefix}/ind{n}/data{idx}.txt" for n in range(1, 5))
        row.append(f"{prefix}/combined/data{idx}.txt")
        self._append_csv(path, ["mode", "dataset_index", "ind1", "ind2", "ind3", "ind4", "combined"], row)

    @staticmethod
    def _append_csv(path: Path, header: list, row: list):
        exists = path.exists()
        with path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            if not exists:
                writer.writerow(header)
            writer.writerow(row)
