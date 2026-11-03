"""Checks for the frozen V2 cause lists (V2_SPEC.md sections 3 to 5).

These tests do not judge whether a cause is *right*; that is the owner's review
(gate G2). They check what a machine can: that every piece of cited evidence
exists in the architecture file with exactly the cited value, that the draft is
bound to the checksum of the architecture it was derived from, that labels are
internally consistent with the stated difficulty operationalization, and that
the structure is complete. Offline and deterministic.
"""

import hashlib
import json
from pathlib import Path

import pytest

from src.models.threat import StrideCategory

ROOT = Path(__file__).resolve().parents[1]
DRAFTS = sorted((ROOT / "benchmark_v2" / "v2.0").glob("*.causes.json"))

STRIDE = {c.value for c in StrideCategory}
EVIDENCE_TYPES = {"direct", "derived", "scenario"}
LEVELS = {"easy", "medium", "hard"}
ROLES = {"primary", "supporting"}
UNSUPPORTED_REASONS = {"no_evidence", "contradicted_by_config", "out_of_scope"}
RISK_CLASSES = {"stride_threat", "recoverability", "detection_gap"}


def _load(path: Path) -> tuple[dict, dict]:
    draft = json.loads(path.read_text())
    architecture = json.loads((ROOT / draft["provenance"]["derived_from"]["file"]).read_text())
    return draft, architecture


def _element_ids(architecture: dict) -> dict[str, str]:
    ids = {c["id"]: "component" for c in architecture["components"]}
    ids.update({f["id"]: "data_flow" for f in architecture["data_flows"]})
    return ids


def _resolve(architecture: dict, path: str):
    """Follow ``components.<id>.<field>[.config.<key>]`` or ``data_flows.<id>.<field>``."""
    section, element_id, *rest = path.split(".")
    value = next(item for item in architecture[section] if item["id"] == element_id)
    for key in rest:
        value = value[key]
    return value


def _element_of(path: str) -> str:
    return path.split(".")[1]


def _all_evidence(draft: dict) -> list[tuple[str, dict]]:
    """Every evidence-like citation in the draft, with a label for failures."""
    cited = []
    for cause in draft["causes"] + draft["candidate_chain_causes"]:
        for item in cause["evidence"]:
            cited.append((cause["ref"], item))
    for case in draft["boundary_cases"]:
        for item in case["based_on"]:
            cited.append((case["ref"], item))
    for entry in draft["unsupported"]:
        for item in entry.get("contradicting_evidence", []):
            cited.append((entry["ref"], item))
    return cited


def test_drafts_exist():
    assert {p.name for p in DRAFTS} == {
        "multi_tenant_saas.causes.json",
        "cloud_ingest_pipeline.causes.json",
    }


@pytest.fixture(params=DRAFTS, ids=lambda p: p.name.removesuffix(".causes.json"))
def loaded(request):
    return _load(request.param)


# --- provenance --------------------------------------------------------------


def test_draft_is_bound_to_the_architecture_checksum(loaded):
    draft, _ = loaded
    source = ROOT / draft["provenance"]["derived_from"]["file"]
    actual = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    assert draft["provenance"]["derived_from"]["sha256_16"] == actual, (
        "architecture file changed since the draft was written"
    )
    assert draft["status"] == "FROZEN" and draft["gt_version"] == "V2.0"
    assert draft["frozen"]["date"] and draft["frozen"]["approved_by"]
    assert "V1 ground truth" in draft["provenance"]["not_used"]
    assert draft["provenance"]["disclosure"]


def test_draft_does_not_reference_v1_ground_truth_or_results_files():
    for path in DRAFTS:
        text = path.read_text()
        assert "ground_truth.json" not in text
        assert "results/" not in text


# --- evidence ----------------------------------------------------------------


def test_every_cited_value_exists_in_the_architecture_with_the_cited_value(loaded):
    draft, architecture = loaded
    cited = _all_evidence(draft)
    assert cited
    for label, item in cited:
        actual = _resolve(architecture, item["path"])
        assert actual == item["observed"], (
            f"{label}: {item['path']} is {actual!r} in the architecture, "
            f"but the draft cites {item['observed']!r}"
        )


# --- confirmed causes --------------------------------------------------------


def test_cause_structure(loaded):
    draft, architecture = loaded
    elements = _element_ids(architecture)
    refs = [c["ref"] for c in draft["causes"]]
    cause_ids = [c["cause_id"] for c in draft["causes"]]
    assert len(set(refs)) == len(refs)
    assert len(set(cause_ids)) == len(cause_ids)

    for cause in draft["causes"]:
        label = cause["ref"]
        assert cause["target"] in elements, label
        assert cause["target_kind"] == elements[cause["target"]], label
        assert cause["cause_id"].startswith(cause["target"] + "."), label
        assert cause["root_cause"].strip() and cause["justification"].strip(), label
        assert cause["evidence_type"] in EVIDENCE_TYPES, label
        assert cause["difficulty"]["level"] in LEVELS, label
        assert cause["difficulty"]["rationale"].strip(), label

        categories = [c["category"] for c in cause["categories"]]
        assert len(set(categories)) == len(categories), label
        assert set(categories) <= STRIDE and len(categories) <= 2, label
        assert all(c["scenario"].strip() for c in cause["categories"]), label

        # Risk class and STRIDE scoring must agree: only stride_threat causes carry categories.
        assert cause["risk_class"] in RISK_CLASSES, label
        assert isinstance(cause["stride_scored"], bool), label
        assert cause["stride_scored"] == (cause["risk_class"] == "stride_threat"), label
        assert bool(categories) == cause["stride_scored"], (
            f"{label}: categories and stride_scored disagree"
        )

        # Every cause separates what the architecture establishes from what is hypothetical.
        assert cause["established"].strip() and cause["hypothetical"].strip(), label

        roles = [e["role"] for e in cause["evidence"]]
        assert set(roles) <= ROLES and "primary" in roles, label
        if cause["evidence_type"] == "derived":
            assert len(cause["evidence"]) >= 2, f"{label}: derived needs two or more facts"


def test_difficulty_labels_follow_the_stated_operationalization(loaded):
    """easy is single-element; hard needs facts from at least two elements."""
    draft, _ = loaded
    for cause in draft["causes"] + draft["candidate_chain_causes"]:
        elements = {_element_of(e["path"]) for e in cause["evidence"]}
        level = cause["difficulty"]["level"]
        if level == "easy":
            assert len(elements) == 1, f"{cause['ref']}: easy but evidence spans {elements}"
            assert cause["evidence_type"] == "direct", cause["ref"]
        if level == "hard":
            assert len(elements) >= 2, f"{cause['ref']}: hard but evidence is on {elements}"


def test_limitations_are_documented_and_match_the_difficulty_distribution(loaded):
    """An empty hard class must be stated as a limitation, not left implicit."""
    draft, _ = loaded
    assert draft["limitations"] and all(item.strip() for item in draft["limitations"])
    levels = {c["difficulty"]["level"] for c in draft["causes"]}
    if "hard" not in levels:
        assert any("hard" in item and "chains" in item for item in draft["limitations"])
    non_stride = [c["ref"] for c in draft["causes"] if not c["stride_scored"]]
    for ref in non_stride:
        assert any(ref in item for item in draft["limitations"]), (
            f"{ref} is not STRIDE-scored but no limitation says so"
        )


# --- boundary, unsupported, candidates ---------------------------------------


def test_boundary_and_unsupported_entries(loaded):
    draft, architecture = loaded
    elements = set(_element_ids(architecture))
    refs = (
        [c["ref"] for c in draft["causes"]]
        + [c["ref"] for c in draft["boundary_cases"]]
        + [c["ref"] for c in draft["unsupported"]]
        + [c["ref"] for c in draft["candidate_chain_causes"]]
    )
    assert len(set(refs)) == len(refs), "refs must be unique across all sections"

    for case in draft["boundary_cases"]:
        assert set(case["targets"]) <= elements, case["ref"]
        assert case["category"] in STRIDE, case["ref"]
        assert case["policy"] == "P1" and case["note"].strip(), case["ref"]

    for entry in draft["unsupported"]:
        label = entry["ref"]
        assert set(entry["targets"]) <= elements, label
        assert entry["category"] in STRIDE, label
        assert entry["reason"] in UNSUPPORTED_REASONS, label
        assert entry["claimed_cause"].strip() and entry["note"].strip(), label
        if entry["reason"] == "contradicted_by_config":
            assert entry.get("contradicting_evidence"), f"{label}: contradiction needs evidence"


def test_candidate_chain_causes_are_consistent(loaded):
    draft, architecture = loaded
    elements = _element_ids(architecture)
    confirmed = {c["ref"] for c in draft["causes"]}
    for cand in draft["candidate_chain_causes"]:
        label = cand["ref"]
        assert cand["target"] in elements, label
        assert cand["category"] in STRIDE, label
        assert cand["evidence_type"] == "derived", label
        assert set(cand["involves"]) <= confirmed and len(cand["involves"]) >= 2, label
        assert cand["difficulty"]["level"] in LEVELS, label
        assert cand["overlap_note"].strip(), label


def test_confirmed_causes_exclude_everything_listed_as_unsupported(loaded):
    """A claimed cause must not be both confirmed and listed as unsupported."""
    draft, _ = loaded
    confirmed_texts = {c["root_cause"].lower() for c in draft["causes"]}
    for entry in draft["unsupported"]:
        assert entry["claimed_cause"].lower() not in confirmed_texts, entry["ref"]


# --- the generated review sheet ----------------------------------------------


def test_review_sheet_is_in_sync_with_the_json_drafts():
    """REVIEW.md is generated; it must never diverge from the JSON it renders."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render_cause_review.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
