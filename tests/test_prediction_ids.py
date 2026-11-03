"""Tests for the stable prediction identifiers (V2 annotation export)."""

import copy
import random

import pytest

from src.evaluation.prediction_ids import (
    assert_unique,
    prediction_uid,
    prediction_uids,
    uids_for_file,
)
from src.evaluation.predictions import read_predictions, write_predictions
from src.models.threat import StrideCategory, Threat


def _threats() -> list[Threat]:
    return [
        Threat(id="t-1", component_id="api", category=StrideCategory.SPOOFING,
               description="first", mitigation="m1"),
        Threat(id="t-2", data_flow_id="flow_a", category=StrideCategory.TAMPERING,
               description="second", mitigation="m2"),
        Threat(id="t-3", component_id="api", category=StrideCategory.SPOOFING,
               description="first", mitigation="m1"),  # identical text, other position
    ]


def _record(approach="rag", run_index=0, model="m", architecture="arch"):
    return {
        "architecture": architecture, "approach": approach, "model": model,
        "run_index": run_index, "timestamp": "2026-01-01T00:00:00+00:00",
        "predictions": [
            {"id": "t-1", "target": "api", "category": "spoofing", "description": "first",
             "mitigation": "m1", "key": "api:spoofing"},
            {"id": "t-2", "target": "flow_a", "category": "tampering", "description": "second",
             "mitigation": "m2", "key": "flow_a:tampering"},
        ],
    }


def test_identifiers_are_deterministic_and_have_a_fixed_format():
    record = _record()
    first, second = prediction_uids(record), prediction_uids(copy.deepcopy(record))
    assert first == second
    assert all(u.startswith("pred-") and len(u) == len("pred-") + 16 for u in first)
    assert len(set(first)) == len(first)


def test_identifier_does_not_depend_on_the_model_assigned_threat_id():
    record = _record()
    renamed = copy.deepcopy(record)
    for i, prediction in enumerate(renamed["predictions"]):
        prediction["id"] = f"completely-different-{i}"
        prediction["key"] = "changed:key"  # the derived key is not part of the identity either
    assert prediction_uids(renamed) == prediction_uids(record)


def test_identifier_does_not_reveal_approach_model_or_run():
    record = _record(approach="agent_pev_noplan", model="llama3.1:8b", run_index=7)
    for uid in prediction_uids(record):
        for secret in ("agent", "pev", "noplan", "llama", "run", "arch"):
            assert secret not in uid


@pytest.mark.parametrize("change", [
    {"approach": "agent_pev"}, {"model": "other"}, {"run_index": 1}, {"architecture": "other"},
])
def test_identical_text_in_another_run_or_approach_gets_another_identifier(change):
    assert prediction_uids(_record()) != prediction_uids(_record(**change))


def test_identifier_changes_when_the_content_changes():
    base = prediction_uids(_record())
    for field, value in (("description", "edited"), ("mitigation", "edited"),
                         ("category", "tampering"), ("target", "web")):
        record = _record()
        record["predictions"][0][field] = value
        changed = prediction_uids(record)
        assert changed[0] != base[0], field
        assert changed[1] == base[1], f"{field}: the other prediction must be unaffected"


def test_identical_predictions_at_different_positions_stay_distinct(tmp_path):
    path = write_predictions(
        approach="rag", model="m", architecture="a", run_index=0, threats=_threats(),
        directory=tmp_path, code={"commit": None, "dirty": None},
    )
    uids = uids_for_file(path)
    assert len(set(uids)) == 3
    record = read_predictions(path)
    assert record["predictions"][0]["description"] == record["predictions"][2]["description"]


def test_identifiers_survive_writing_and_rereading_and_ignore_code_version(tmp_path):
    kwargs = dict(approach="rag", model="m", architecture="a", run_index=0, threats=_threats())
    path = write_predictions(directory=tmp_path, code={"commit": "a" * 40, "dirty": False},
                             **kwargs)
    record = read_predictions(path)
    assert uids_for_file(path) == prediction_uids(record) == uids_for_file(path)
    other = copy.deepcopy(record)
    other["code"] = {"commit": "b" * 40, "dirty": True}
    assert prediction_uids(other) == prediction_uids(record)


def test_randomizing_an_export_does_not_change_which_identifier_names_which_prediction():
    record = _record()
    uids = prediction_uids(record)
    text_by_uid = {u: p["description"] for u, p in zip(uids, record["predictions"], strict=True)}
    for seed in range(5):
        shuffled = uids[:]
        random.Random(seed).shuffle(shuffled)
        assert {u: text_by_uid[u] for u in shuffled} == text_by_uid
        # Recomputing from the stored record gives the same mapping whatever the export order was.
        recomputed = {prediction_uid(record, i): record["predictions"][i]["description"]
                      for i in range(len(record["predictions"]))}
        assert recomputed == text_by_uid


def test_assert_unique_detects_collisions():
    assert_unique(["a", "b"])
    with pytest.raises(ValueError, match="duplicate"):
        assert_unique(["a", "b", "a"])
