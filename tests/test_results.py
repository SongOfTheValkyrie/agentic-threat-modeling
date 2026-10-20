"""Tests for serializing and appending benchmark run records.

These pin down the on-disk record shape that aggregate.py later consumes:
rounded metrics, the per-difficulty block (only classes that appear), optional
usage fields, and the append-only JSONL behaviour.
"""

import json

from src.evaluation.evaluator import DifficultyRecall, EvaluationResult
from src.evaluation.results import DEFAULT_RESULTS_PATH, RunRecord, append_result
from src.models.threat import Difficulty


def _result() -> EvaluationResult:
    return EvaluationResult(
        true_positives=3,
        false_positives=1,
        false_negatives=2,
        precision=0.75,
        recall=0.6,
        f1=0.666666,
        true_positive_keys=["web:spoofing", "db:information_disclosure", "api:tampering"],
        false_positive_keys=["cache:spoofing"],
        false_negative_keys=["db:tampering", "api:repudiation"],
    )


def _by_difficulty() -> dict[Difficulty, DifficultyRecall]:
    return {
        Difficulty.EASY: DifficultyRecall(detected=2, total=2, recall=1.0),
        Difficulty.MEDIUM: DifficultyRecall(detected=0, total=0, recall=0.0),
        Difficulty.HARD: DifficultyRecall(detected=1, total=3, recall=0.333333),
    }


def _record(**overrides) -> RunRecord:
    defaults = dict(
        approach="rag",
        model="llama3.1:8b",
        architecture="simple_web_api",
        result=_result(),
        by_difficulty=_by_difficulty(),
        latency_seconds=12.3456,
        num_threats=4,
        run_index=2,
    )
    defaults.update(overrides)
    return RunRecord(**defaults)


def test_to_dict_core_fields_and_rounding():
    d = _record().to_dict()

    assert d["approach"] == "rag"
    assert d["model"] == "llama3.1:8b"
    assert d["architecture"] == "simple_web_api"
    assert d["run_index"] == 2
    assert d["true_positives"] == 3
    assert d["false_positives"] == 1
    assert d["false_negatives"] == 2
    assert d["precision"] == 0.75
    assert d["recall"] == 0.6
    assert d["f1"] == 0.6667  # rounded to 4 decimals
    assert d["latency_seconds"] == 12.346  # rounded to 3 decimals
    assert d["num_threats"] == 4
    assert "timestamp" in d


def test_to_dict_includes_only_difficulty_classes_with_ground_truth():
    d = _record().to_dict()
    rbd = d["recall_by_difficulty"]

    # medium had total=0, so it is omitted.
    assert set(rbd) == {"easy", "hard"}
    assert rbd["easy"] == {"detected": 2, "total": 2, "recall": 1.0}
    assert rbd["hard"]["recall"] == 0.3333


def test_to_dict_includes_threat_level_keys():
    d = _record().to_dict()
    assert d["matched_keys"] == [
        "web:spoofing", "db:information_disclosure", "api:tampering"
    ]
    assert d["missed_keys"] == ["db:tampering", "api:repudiation"]
    assert d["unmatched_prediction_keys"] == ["cache:spoofing"]
    # Counts and key lists stay consistent.
    assert len(d["matched_keys"]) == d["true_positives"]
    assert len(d["missed_keys"]) == d["false_negatives"]
    assert len(d["unmatched_prediction_keys"]) == d["false_positives"]


def test_to_dict_omits_usage_fields_when_none():
    d = _record().to_dict()
    assert "llm_calls" not in d
    assert "retrieval_calls" not in d
    assert "tokens" not in d


def test_to_dict_includes_usage_fields_when_present():
    d = _record(llm_calls=7, retrieval_calls=7, tokens=1234).to_dict()
    assert d["llm_calls"] == 7
    assert d["retrieval_calls"] == 7
    assert d["tokens"] == 1234


def test_append_result_writes_one_json_line_per_call(tmp_path):
    path = tmp_path / "nested" / "results.jsonl"  # parent must be created

    append_result(_record(run_index=0), path=path)
    append_result(_record(run_index=1), path=path)

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    records = [json.loads(line) for line in lines]
    assert [r["run_index"] for r in records] == [0, 1]
    # Each line is independently valid JSON (true JSONL, not a JSON array).
    assert all(isinstance(r, dict) for r in records)


def test_default_results_path_is_under_results_dir():
    assert DEFAULT_RESULTS_PATH.endswith("results.jsonl")
