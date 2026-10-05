"""Persist benchmark runs as JSON Lines for later aggregation.

Each run (one approach on one architecture) is appended as a single JSON object
to a .jsonl file. Appending (never overwriting) means repeated runs accumulate,
which is what the planned multi-run averaging needs.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from src.evaluation.evaluator import DifficultyRecall, EvaluationResult
from src.models.threat import Difficulty

DEFAULT_RESULTS_PATH = "results/results.jsonl"


@dataclass
class RunRecord:
    """One evaluated run, ready to serialize."""

    approach: str
    model: str
    architecture: str
    result: EvaluationResult
    by_difficulty: dict[Difficulty, DifficultyRecall]
    latency_seconds: float
    num_threats: int
    run_index: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "approach": self.approach,
            "model": self.model,
            "architecture": self.architecture,
            "run_index": self.run_index,
            "true_positives": self.result.true_positives,
            "false_positives": self.result.false_positives,
            "false_negatives": self.result.false_negatives,
            "precision": round(self.result.precision, 4),
            "recall": round(self.result.recall, 4),
            "f1": round(self.result.f1, 4),
            "recall_by_difficulty": {
                d.value: {
                    "detected": self.by_difficulty[d].detected,
                    "total": self.by_difficulty[d].total,
                    "recall": round(self.by_difficulty[d].recall, 4),
                }
                for d in Difficulty
                if self.by_difficulty[d].total
            },
            "latency_seconds": round(self.latency_seconds, 3),
            "num_threats": self.num_threats,
        }


def append_result(record: RunRecord, path: str | Path = DEFAULT_RESULTS_PATH) -> None:
    """Append one run record as a JSON line, creating the file if needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(record.to_dict()) + "\n")
