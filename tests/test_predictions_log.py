"""Tests for the V2 prediction logging (V2_SPEC.md §6).

Logging must record exactly what a modeler returned, in order and with full
text, in an immutable per-run file, and must not change anything else.
"""

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import golden_support as gs
import pytest

import main
from src.agent.structured import StructuredAgentThreatModeler
from src.deterministic.modeler import DeterministicThreatModeler
from src.evaluation import predictions
from src.evaluation.evaluator import evaluate
from src.evaluation.predictions import (
    code_version,
    read_predictions,
    threat_to_dict,
    write_predictions,
)
from src.evaluation.results import RunRecord
from src.models.loader import load_architecture
from src.models.threat import StrideCategory, Threat
from src.RAG.knowledge import load_knowledge_base
from src.RAG.retriever import KeywordRetriever

ROOT = Path(__file__).resolve().parents[1]


def _fields(prediction: dict) -> tuple:
    return (
        prediction["target"],
        prediction["category"],
        prediction["description"],
        prediction["mitigation"],
    )


def _threat_fields(threat: Threat) -> tuple:
    return (
        threat.component_id or threat.data_flow_id,
        threat.category.value,
        threat.description,
        threat.mitigation,
    )


# --- serialization ----------------------------------------------------------


def test_threat_to_dict_for_component_and_flow():
    component = Threat(
        id="c1", component_id="web", category=StrideCategory.SPOOFING,
        description="d1", mitigation="m1",
    )
    flow = Threat(
        id="f1", data_flow_id="flow_db", category=StrideCategory.TAMPERING,
        description="d2", mitigation="m2",
    )
    assert threat_to_dict(component) == {
        "id": "c1", "target": "web", "target_kind": "component",
        "category": "spoofing", "description": "d1", "mitigation": "m1",
        "key": "web:spoofing",
    }
    assert threat_to_dict(flow)["target_kind"] == "data_flow"
    assert threat_to_dict(flow)["key"] == "flow_db:tampering"


def test_write_then_read_matches_threats_field_by_field(tmp_path, sample_architecture):
    threats = DeterministicThreatModeler().analyze(sample_architecture)
    assert threats, "fixture architecture should produce threats"

    path = write_predictions(
        approach="deterministic", model="none", architecture="arch_test",
        run_index=4, threats=threats, directory=tmp_path,
    )
    record = read_predictions(path)

    assert record["approach"] == "deterministic"
    assert record["model"] == "none"
    assert record["architecture"] == "arch_test"
    assert record["run_index"] == 4
    assert record["num_predictions"] == len(threats)
    assert [_fields(p) for p in record["predictions"]] == [_threat_fields(t) for t in threats]
    assert [p["id"] for p in record["predictions"]] == [t.id for t in threats]


def test_keys_in_file_equal_the_keys_the_v1_evaluator_derives(tmp_path, sample_architecture,
                                                              ground_truth):
    threats = DeterministicThreatModeler().analyze(sample_architecture)
    path = write_predictions(
        approach="deterministic", model="none", architecture="arch_test",
        run_index=0, threats=threats, directory=tmp_path,
    )
    logged_keys = {p["key"] for p in read_predictions(path)["predictions"]}
    result = evaluate(threats, ground_truth)
    assert logged_keys == set(result.true_positive_keys) | set(result.false_positive_keys)


# --- immutability -----------------------------------------------------------


def test_prediction_file_is_read_only(tmp_path):
    path = write_predictions(
        approach="rag", model="m", architecture="a", run_index=0, threats=[], directory=tmp_path,
    )
    assert path.stat().st_mode & 0o222 == 0


def test_existing_file_is_never_overwritten(tmp_path, monkeypatch):
    class FixedTime:
        @staticmethod
        def now(tz=None):
            return datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)

    monkeypatch.setattr(predictions, "datetime", FixedTime)
    kwargs = dict(approach="rag", model="m", architecture="a", run_index=0,
                  threats=[], directory=tmp_path)
    write_predictions(**kwargs)
    with pytest.raises(FileExistsError):
        write_predictions(**kwargs)


# --- code version -----------------------------------------------------------


def test_code_version_degrades_gracefully_without_git(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("git not available")

    monkeypatch.setattr(subprocess, "run", fail)
    assert code_version() == {"commit": None, "dirty": None}


def test_code_version_reports_a_commit_inside_the_repository():
    version = code_version()
    assert set(version) == {"commit", "dirty"}
    if version["commit"] is not None:  # tolerate an export without .git
        assert len(version["commit"]) == 40


# --- results record ----------------------------------------------------------


def test_run_record_includes_predictions_file_only_when_set(sample_architecture, ground_truth):
    result = evaluate(DeterministicThreatModeler().analyze(sample_architecture), ground_truth)
    from src.evaluation.evaluator import evaluate_by_difficulty

    by_difficulty = evaluate_by_difficulty([], ground_truth)
    base = dict(
        approach="x", model="m", architecture="a", result=result,
        by_difficulty=by_difficulty, latency_seconds=1.0, num_threats=1,
    )
    assert "predictions_file" not in RunRecord(**base).to_dict()
    assert RunRecord(**base, predictions_file="p.json").to_dict()["predictions_file"] == "p.json"


# --- end to end through main.run_benchmark -----------------------------------


def _stub_pev(architecture):
    llm = gs.StubLLM(architecture)
    llm.model = "stub-model"  # run_benchmark reads the model name from the client
    retriever = KeywordRetriever(load_knowledge_base(ROOT / "data" / "knowledge_base.json"))
    return StructuredAgentThreatModeler(llm=llm, retriever=retriever)


def test_run_benchmark_logs_predictions_that_equal_trace_and_returned_threats(
    tmp_path, monkeypatch,
):
    name = "simple_web_api"
    (tmp_path / "benchmark").mkdir()
    for suffix in (".json", ".ground_truth.json"):
        shutil.copy(ROOT / "benchmark" / f"{name}{suffix}", tmp_path / "benchmark")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "TRACE", True)

    architecture = load_architecture(tmp_path / "benchmark" / f"{name}.json")
    main.run_benchmark(_stub_pev(architecture), name, run_index=2)

    # The results row points at the prediction file.
    rows = [json.loads(line) for line in (tmp_path / "results" / "results.jsonl").read_text()
            .splitlines()]
    assert len(rows) == 1
    record = read_predictions(rows[0]["predictions_file"])
    assert (record["approach"], record["model"], record["architecture"], record["run_index"]) == (
        "agent_pev", "stub-model", name, 2,
    )
    assert rows[0]["num_threats"] == record["num_predictions"]

    # An independent run of the same deterministic setup returns the same threats.
    expected = _stub_pev(architecture).analyze(architecture)
    assert [_fields(p) for p in record["predictions"]] == [_threat_fields(t) for t in expected]

    # The trace written for the same run holds the same texts, in the same order.
    (trace_file,) = list((tmp_path / "results" / "traces").glob("*.json"))
    trace = json.loads(trace_file.read_text())
    from_trace = [
        (e["element_id"], c["category"], c["description"], c["mitigation"])
        for e in trace["elements"]
        for c in e["confirmed_threats"]
    ]
    assert from_trace == [_fields(p) for p in record["predictions"]]


def test_run_benchmark_for_deterministic_baseline_has_no_model(tmp_path, monkeypatch):
    name = "simple_web_api"
    (tmp_path / "benchmark").mkdir()
    for suffix in (".json", ".ground_truth.json"):
        shutil.copy(ROOT / "benchmark" / f"{name}{suffix}", tmp_path / "benchmark")
    monkeypatch.chdir(tmp_path)

    main.run_benchmark(DeterministicThreatModeler(), name, run_index=0)

    row = json.loads((tmp_path / "results" / "results.jsonl").read_text().splitlines()[0])
    record = read_predictions(row["predictions_file"])
    assert (row["approach"], row["model"]) == ("deterministic", "none")
    assert record["model"] == "none"
    assert "llm_calls" not in row  # usage fields stay absent for the baseline
