"""Consistency checks for the V2 cause lists (owner decisions A to F at gate G2).

Three questions are answered by tests, offline:

1. The two recall denominators (Threat Cause Recall over the STRIDE-mapped
   causes, Security Control Gap Recall over all causes) match the cause fields.
2. STRIDE mappings follow unambiguous rules.
3. Both recalls can be computed from the same stored prediction file and one
   label per prediction.

Mutation tests change an in-memory copy of the drafts and must be detected.
"""

import copy
import importlib.util
from pathlib import Path

import golden_support as gs
import pytest

from src.agent.structured import StructuredAgentThreatModeler
from src.evaluation.predictions import write_predictions
from src.models.loader import load_architecture
from src.RAG.knowledge import load_knowledge_base
from src.RAG.retriever import KeywordRetriever

ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "check_cause_consistency", ROOT / "scripts" / "check_cause_consistency.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cc = _load_script()


@pytest.fixture
def drafts():
    return cc.load_drafts()


# --- 1. denominators -----------------------------------------------------------------


def test_denominators_are_15_and_17(drafts):
    failures, numbers = cc.check_denominators(drafts)
    assert failures == []
    assert numbers["pooled"] == {
        "threat_cause_recall_denominator": 15,
        "security_control_gap_recall_denominator": 17,
    }
    per = numbers["per_architecture"]
    assert per["multi_tenant_saas"]["threat_cause_recall_denominator"] == 6
    assert per["multi_tenant_saas"]["security_control_gap_recall_denominator"] == 6
    assert per["cloud_ingest_pipeline"]["threat_cause_recall_denominator"] == 9
    assert per["cloud_ingest_pipeline"]["security_control_gap_recall_denominator"] == 11
    assert per["cloud_ingest_pipeline"]["control_gap_only"] == ["CIP-04", "CIP-11"]


def test_candidate_chains_are_preserved_but_in_no_denominator(drafts):
    chains = {x["ref"] for d in drafts.values() for x in d["candidate_chain_causes"]}
    assert chains == {"MTS-X1", "MTS-X2", "CIP-X1", "CIP-X2"}
    for draft in drafts.values():
        assert draft["chain_policy"].strip()
        for refs in draft["recall_sets"].values():
            assert not set(refs) & chains


def test_declared_recall_sets_must_equal_the_derived_ones(drafts):
    mutated = copy.deepcopy(drafts)
    mutated["cloud_ingest_pipeline"]["recall_sets"]["threat_cause_recall"].append("CIP-11")
    failures, _ = cc.check_denominators(mutated)
    assert any("threat_cause_recall differs" in f for f in failures)

    mutated = copy.deepcopy(drafts)
    mutated["cloud_ingest_pipeline"]["recall_sets"]["security_control_gap_recall"].remove("CIP-04")
    failures, _ = cc.check_denominators(mutated)
    assert any("security_control_gap_recall differs" in f for f in failures)


def test_a_chain_or_boundary_ref_in_a_denominator_is_detected(drafts):
    mutated = copy.deepcopy(drafts)
    mutated["multi_tenant_saas"]["recall_sets"]["security_control_gap_recall"].append("MTS-X1")
    failures, _ = cc.check_denominators(mutated)
    assert failures


def test_missing_recall_sets_are_detected(drafts):
    mutated = copy.deepcopy(drafts)
    del mutated["multi_tenant_saas"]["recall_sets"]
    failures, _ = cc.check_denominators(mutated)
    assert any("recall_sets.threat_cause_recall is missing" in f for f in failures)


# --- 2. STRIDE mapping ---------------------------------------------------------------


def test_stride_mapping_rules_hold_and_counts_are_20_entries_17_keys(drafts):
    failures, info = cc.check_stride_mapping(drafts)
    assert failures == []
    assert (info["entries"], info["distinct_keys"]) == (20, 17)


def test_control_gaps_carry_no_stride_category(drafts):
    by_ref = {c["ref"]: c for d in drafts.values() for c in d["causes"]}
    for ref, risk_class in (("CIP-04", "recoverability"), ("CIP-11", "detection_gap")):
        assert by_ref[ref]["risk_class"] == risk_class
        assert by_ref[ref]["categories"] == []


def test_logging_causes_stay_repudiation(drafts):
    by_ref = {c["ref"]: c for d in drafts.values() for c in d["causes"]}
    for ref in ("CIP-05", "CIP-09", "CIP-10"):
        assert [k["category"] for k in by_ref[ref]["categories"]] == ["repudiation"], ref


def test_overprivileged_roles_are_treated_the_same(drafts):
    """Decision B: CIP-06 and MTS-06 have the same mapping, note and conditional scenario."""
    by_ref = {c["ref"]: c for d in drafts.values() for c in d["causes"]}
    for ref in ("CIP-06", "MTS-06"):
        cause = by_ref[ref]
        assert [k["category"] for k in cause["categories"]] == ["elevation_of_privilege"], ref
        assert cause["stride_mapping_note"].strip(), ref
        assert "No escalation path is established or claimed" in cause["stride_mapping_note"], ref
        assert cause["categories"][0]["scenario"].startswith("If "), ref
        assert "overprivileged role model" in cause["root_cause"], ref
    _, info = cc.check_stride_mapping(drafts)
    assert sorted(info["coarse_mappings"]) == ["CIP-06", "MTS-06"]


def test_cip04_stays_easy(drafts):
    by_ref = {c["ref"]: c for d in drafts.values() for c in d["causes"]}
    assert by_ref["CIP-04"]["difficulty"]["level"] == "easy"


def test_no_category_is_marked_required(drafts):
    """Decision D: no per-category required flag; categories carry only a scenario."""
    for draft in drafts.values():
        assert "None is required" in draft["category_semantics"]
        for cause in draft["causes"]:
            for entry in cause["categories"]:
                assert set(entry) == {"category", "scenario"}, cause["ref"]


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda c: c["categories"].append({"category": "tampering", "scenario": "x"}),
         "control gap must not carry"),
        (lambda c: c.update(stride_scored=True), "disagrees"),
    ],
)
def test_control_gap_with_stride_mapping_is_detected(drafts, mutate, expected):
    mutated = copy.deepcopy(drafts)
    cause = next(c for c in mutated["cloud_ingest_pipeline"]["causes"] if c["ref"] == "CIP-11")
    mutate(cause)
    failures, _ = cc.check_stride_mapping(mutated)
    assert any(expected in f for f in failures), failures


def test_three_categories_duplicates_and_unknown_names_are_detected(drafts):
    for change, expected in (
        (lambda cats: cats.extend([
            {"category": "spoofing", "scenario": "x"}, {"category": "tampering", "scenario": "x"},
        ]), "more than 2"),
        (lambda cats: cats.append(dict(cats[0])), "duplicate category"),
        (lambda cats: cats.append({"category": "bogus", "scenario": "x"}), "unknown category"),
    ):
        mutated = copy.deepcopy(drafts)
        cause = next(c for c in mutated["multi_tenant_saas"]["causes"] if c["ref"] == "MTS-06")
        change(cause["categories"])
        failures, _ = cc.check_stride_mapping(mutated)
        assert any(expected in f for f in failures), (expected, failures)


def test_threat_cause_without_category_is_detected(drafts):
    mutated = copy.deepcopy(drafts)
    cause = next(c for c in mutated["multi_tenant_saas"]["causes"] if c["ref"] == "MTS-01")
    cause["categories"] = []
    cause["stride_scored"] = False
    failures, _ = cc.check_stride_mapping(mutated)
    assert any("needs at least one STRIDE category" in f for f in failures)


def test_key_overlaps_are_inventoried_not_hidden(drafts):
    """The coarse key cannot tell some causes apart; the report must say which."""
    _, info = cc.check_stride_mapping(drafts)
    assert info["shared_keys"]["api:elevation_of_privilege"] == ["MTS-01", "MTS-02"]
    assert info["shared_keys"]["api:information_disclosure"] == ["MTS-01", "MTS-02"]
    assert info["shared_keys"]["raw_bucket:information_disclosure"] == ["CIP-02", "CIP-03"]
    excluded = {(ref, key) for ref, _, key, _ in info["excluded_entries_sharing_a_confirmed_key"]}
    assert ("MTS-U2", "shared_db:information_disclosure") in excluded
    # CIP-11 has no key of its own, but its target carries CIP-10's repudiation key.
    gaps = dict(info["control_gap_targets_with_stride_keys"])
    assert gaps["CIP-11"] == ["monitoring:repudiation"]
    assert "raw_bucket:information_disclosure" in gaps["CIP-04"]


# --- 3. both recalls from one set of stored predictions ----------------------------------


def _stored_run(tmp_path: Path, architecture_name: str) -> tuple[Path, int]:
    root = ROOT
    architecture = load_architecture(root / "benchmark" / f"{architecture_name}.json")
    llm = gs.StubLLM(architecture)
    retriever = KeywordRetriever(load_knowledge_base(root / "data" / "knowledge_base.json"))
    threats = StructuredAgentThreatModeler(llm=llm, retriever=retriever).analyze(architecture)
    path = write_predictions(
        approach="agent_pev", model="stub", architecture=architecture_name, run_index=0,
        threats=threats, directory=tmp_path, code={"commit": None, "dirty": None},
    )
    return path, len(threats)


def _labels(total: int, assigned: dict[int, str]) -> list[str]:
    return [assigned.get(i, "none") for i in range(total)]


def test_both_recalls_come_from_the_same_stored_file_and_labels(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "cloud_ingest_pipeline")
    assert total >= 6
    labels = _labels(total, {0: "CIP-01", 1: "CIP-04", 2: "CIP-11", 3: "CIP-07", 4: "CIP-10"})

    result = cc.score_prediction_file(path, labels, drafts["cloud_ingest_pipeline"])

    assert result["found"] == ["CIP-01", "CIP-04", "CIP-07", "CIP-10", "CIP-11"]
    assert result["threat_cause_recall"] == (3, 9)  # CIP-01, CIP-07, CIP-10
    assert result["security_control_gap_recall"] == (5, 11)  # plus CIP-04 and CIP-11
    assert result["found_control_gap_only"] == ["CIP-04", "CIP-11"]
    assert result["predictions"] == total


def test_the_control_gap_recall_numerator_contains_the_threat_numerator(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "cloud_ingest_pipeline")
    refs = [c["ref"] for c in drafts["cloud_ingest_pipeline"]["causes"]]
    for subset in ([], refs[:3], refs[3:], refs):
        labels = _labels(total, {i: ref for i, ref in enumerate(subset[:total])})
        result = cc.score_prediction_file(path, labels, drafts["cloud_ingest_pipeline"])
        threat_found, _ = result["threat_cause_recall"]
        gap_found, _ = result["security_control_gap_recall"]
        assert threat_found <= gap_found
        assert gap_found - threat_found == len(result["found_control_gap_only"])


def test_a_cause_counts_once_however_often_it_is_predicted(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    labels = _labels(total, {i: "MTS-03" for i in range(total)})
    result = cc.score_prediction_file(path, labels, drafts["multi_tenant_saas"])
    assert result["threat_cause_recall"] == (1, 6)
    assert result["security_control_gap_recall"] == (1, 6)


def test_a_correct_root_cause_counts_whatever_stride_the_prediction_named(tmp_path, drafts):
    """Decision D: the recall result does not depend on the stored category of a prediction."""
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    # Same labels, regardless of which category each stored prediction carries.
    labels = _labels(total, {0: "MTS-01", 1: "MTS-06"})
    result = cc.score_prediction_file(path, labels, drafts["multi_tenant_saas"])
    assert result["threat_cause_recall"] == (2, 6)


def test_non_cause_labels_find_nothing(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    labels = ["none", "unsure", "new_cause_proposed"] * total
    result = cc.score_prediction_file(path, labels[:total], drafts["multi_tenant_saas"])
    assert result["threat_cause_recall"] == (0, 6)
    assert result["security_control_gap_recall"] == (0, 6)


def test_labels_of_other_architectures_and_chain_refs_are_rejected(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    for bad in ("CIP-01", "MTS-X1", "MTS-B1", "MTS-U2", "nonsense"):
        with pytest.raises(ValueError, match="no cause"):
            cc.score_prediction_file(path, _labels(total, {0: bad}), drafts["multi_tenant_saas"])


def test_wrong_architecture_or_label_count_is_rejected(tmp_path, drafts):
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    with pytest.raises(ValueError, match="not cloud_ingest_pipeline"):
        cc.score_prediction_file(path, _labels(total, {}), drafts["cloud_ingest_pipeline"])
    with pytest.raises(ValueError, match="labels for"):
        cc.score_prediction_file(path, _labels(total - 1, {}), drafts["multi_tenant_saas"])


def test_scoring_reads_only_labels_not_prediction_text(tmp_path, drafts):
    """The two recalls are functions of the label set; the prediction file is only validated."""
    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    labels = _labels(total, {0: "MTS-02", 2: "MTS-05"})
    first = cc.score_prediction_file(path, labels, drafts["multi_tenant_saas"])
    assert first == cc.score_prediction_file(path, list(labels), drafts["multi_tenant_saas"])
    assert first == {**cc.recall_from_labels(drafts["multi_tenant_saas"], labels),
                     "predictions": total}


def test_report_exit_code_is_zero_on_the_committed_drafts(capsys):
    assert cc.report() == 0
    out = capsys.readouterr().out
    assert "pooled: 15 and 17" in out
    assert "Consistency checks passed." in out


# --- D23: control-gap claims in the coarse metric and in cause precision -----------------


def _prediction(target: str, category: str, text: str = "x", kind: str = "component") -> dict:
    return {
        "id": f"model-{target}-{category}", "target": target, "target_kind": kind,
        "category": category, "description": text, "mitigation": "m",
        "key": f"{target}:{category}",
    }


def _v1_ground_truth() -> list:
    """A stand-in for the frozen V1 ground truth: only the keys matter for the V1 evaluator."""
    from src.models.threat import StrideCategory, Threat

    def gt(target: str, category: StrideCategory) -> Threat:
        return Threat(id=f"{target}:{category.value}", component_id=target, category=category,
                      description="v1", mitigation="v1")

    return [
        gt("monitoring", StrideCategory.REPUDIATION),
        gt("raw_bucket", StrideCategory.INFORMATION_DISCLOSURE),
        gt("ingest_api", StrideCategory.DENIAL_OF_SERVICE),
    ]


def test_a_cip11_prediction_that_names_repudiation_hits_the_v1_key_of_cip10(drafts):
    """The case from the G2 review: right root cause CIP-11, wrong STRIDE label repudiation."""
    draft = drafts["cloud_ingest_pipeline"]
    predictions = [
        _prediction("monitoring", "repudiation", "Alerting is disabled, nobody is notified."),
        _prediction("raw_bucket", "information_disclosure", "Public bucket."),
        _prediction("ingest_api", "spoofing", "Something generic."),
    ]
    labels = ["CIP-11", "CIP-02", "none"]

    scores = cc.coarse_scores(draft, predictions, labels, _v1_ground_truth())

    # Unchanged V1 key score: the prediction hits the key monitoring:repudiation.
    v1 = scores["v1_key_score"]
    assert "monitoring:repudiation" in v1["tp_keys"]
    assert (v1["tp"], v1["fp"], v1["fn"]) == (2, 1, 1)
    # Cleaned V2 coarse score: the CIP-11 prediction is out, it credits nothing and costs nothing.
    v2 = scores["v2_coarse"]
    assert scores["excluded_predictions"] == 1
    assert scores["excluded_keys"] == ["monitoring:repudiation"]
    assert scores["scored_predictions"] == 2
    assert "monitoring:repudiation" not in v2["tp_keys"]
    assert "monitoring:repudiation" not in v2["fp_keys"]
    assert "monitoring:repudiation" in v2["fn_keys"], "CIP-10's key is not credited by CIP-11"
    assert v2["tp_keys"] == ["raw_bucket:information_disclosure"]
    assert v2["fp_keys"] == ["ingest_api:spoofing"]
    # The two scores are different metrics.
    assert (v1["tp"], v1["fp"]) != (v2["tp"], v2["fp"])
    assert v1["precision"] != v2["precision"]

    # The same predictions also give both cause recalls, and CIP-10 is not found by this claim.
    recall = cc.recall_from_labels(draft, labels)
    assert recall["found"] == ["CIP-02", "CIP-11"]
    assert recall["threat_cause_recall"] == (1, 9)
    assert recall["security_control_gap_recall"] == (2, 11)


def test_cip10_is_credited_in_the_v2_coarse_score_by_its_own_prediction(drafts):
    draft = drafts["cloud_ingest_pipeline"]
    predictions = [
        _prediction("monitoring", "repudiation", "Alerting is disabled."),
        _prediction("monitoring", "repudiation", "Logs are not retained."),
    ]
    scores = cc.coarse_scores(draft, predictions, ["CIP-11", "CIP-10"], _v1_ground_truth())
    assert scores["excluded_predictions"] == 1
    assert scores["v2_coarse"]["tp_keys"] == ["monitoring:repudiation"]
    assert scores["v2_coarse"]["fp"] == 0


def test_a_cip04_prediction_naming_tampering_is_excluded_not_a_false_positive(drafts):
    draft = drafts["cloud_ingest_pipeline"]
    predictions = [_prediction("raw_bucket", "tampering", "Objects cannot be restored.")]
    scores = cc.coarse_scores(draft, predictions, ["CIP-04"], _v1_ground_truth())
    assert scores["v1_key_score"]["fp_keys"] == ["raw_bucket:tampering"]  # V1 key rules: FP
    assert scores["v2_coarse"]["fp"] == 0 and scores["v2_coarse"]["tp"] == 0
    assert scores["excluded_predictions"] == 1 and scores["scored_predictions"] == 0


def test_unmatched_and_unsupported_predictions_stay_in_precision(drafts):
    """Point 3: only control-gap claims are excluded, nothing else is dropped wholesale."""
    draft = drafts["cloud_ingest_pipeline"]
    predictions = [
        _prediction("ingest_api", "spoofing", "generic"),
        _prediction("warehouse", "tampering", "generic"),
        _prediction("warehouse", "spoofing", "unclear"),
        _prediction("raw_bucket", "information_disclosure", "public"),
        _prediction("processing_cluster", "tampering", "new idea"),
    ]
    labels = ["none", "none", "unsure", "CIP-02", "new_cause_proposed"]

    scores = cc.coarse_scores(draft, predictions, labels, _v1_ground_truth())
    assert scores["excluded_predictions"] == 0
    assert scores["scored_predictions"] == 5
    assert scores["v2_coarse"]["fp"] == 4 and scores["v2_coarse"]["tp"] == 1

    claims = cc.cause_claim_counts(draft, labels)
    assert (claims["mapped"], claims["pending_review"], claims["unsupported"]) == (1, 2, 2)
    assert claims["precision_lower"] == pytest.approx(1 / 5)
    assert claims["precision_upper"] == pytest.approx(3 / 5)


def test_control_gap_claims_are_mapped_findings_in_cause_precision(drafts):
    draft = drafts["cloud_ingest_pipeline"]
    labels = ["CIP-04", "CIP-11", "CIP-02", "none"]
    claims = cc.cause_claim_counts(draft, labels)
    assert claims["mapped"] == 3
    assert claims["mapped_control_gaps"] == ["CIP-04", "CIP-11"]
    assert claims["unsupported"] == 1
    assert claims["precision_lower"] == pytest.approx(3 / 4)
    # Repeating a cause adds no claim: precision counts distinct mapped causes.
    assert cc.cause_claim_counts(draft, ["CIP-11", "CIP-11", "CIP-11"])["mapped"] == 1


def test_a_key_match_with_a_different_cause_still_counts_in_the_coarse_score(drafts):
    """Spec 7.2: key matches, cause differs -> TP in the coarse metric, cause not found."""
    draft = drafts["cloud_ingest_pipeline"]
    predictions = [_prediction("raw_bucket", "information_disclosure", "wrong reason")]
    scores = cc.coarse_scores(draft, predictions, ["none"], _v1_ground_truth())
    assert scores["v2_coarse"]["tp_keys"] == ["raw_bucket:information_disclosure"]
    assert cc.recall_from_labels(draft, ["none"])["found"] == []


def test_without_control_gap_labels_v2_coarse_is_the_plain_evaluator_on_the_v2_keys(drafts):
    from src.evaluation import evaluator

    draft = drafts["cloud_ingest_pipeline"]
    predictions = [_prediction("ingest_api", "denial_of_service"),
                   _prediction("monitoring", "repudiation")]
    scores = cc.coarse_scores(draft, predictions, ["CIP-01", "CIP-10"], _v1_ground_truth())
    direct = evaluator.evaluate(
        cc._threats_from_records(predictions), cc.v2_key_ground_truth(draft)
    )
    assert scores["v2_coarse"]["tp_keys"] == direct.true_positive_keys
    assert scores["v2_coarse"]["fn_keys"] == direct.false_negative_keys
    assert scores["excluded_predictions"] == 0
    # CIP-06 is part of the V2 keys: 8 distinct keys in this architecture.
    assert scores["v2_key_denominator"] == 8
    assert cc.evaluate is evaluator.evaluate, "the V1 evaluator function is used, not a copy"


def test_coarse_scores_reject_a_label_count_mismatch(drafts):
    with pytest.raises(ValueError, match="labels for"):
        cc.coarse_scores(drafts["cloud_ingest_pipeline"], [_prediction("a", "spoofing")], [],
                         _v1_ground_truth())


def test_labels_keyed_by_stable_identifier_are_joined_to_the_stored_file(tmp_path, drafts):
    from src.evaluation.prediction_ids import uids_for_file

    path, total = _stored_run(tmp_path, "multi_tenant_saas")
    uids = uids_for_file(path)
    by_uid = {uid: "none" for uid in uids}
    by_uid[uids[0]] = "MTS-01"
    by_uid[uids[3]] = "MTS-06"
    labels = cc.labels_in_file_order(path, by_uid)
    assert labels[0] == "MTS-01" and labels[3] == "MTS-06" and len(labels) == total
    # The order in which an export lists predictions does not matter.
    shuffled = dict(reversed(list(by_uid.items())))
    assert cc.labels_in_file_order(path, shuffled) == labels
    result = cc.score_prediction_file(path, labels, drafts["multi_tenant_saas"])
    assert result["threat_cause_recall"] == (2, 6)


def test_labels_for_the_wrong_or_an_incomplete_set_of_predictions_are_rejected(tmp_path):
    from src.evaluation.prediction_ids import uids_for_file

    path, _ = _stored_run(tmp_path, "multi_tenant_saas")
    uids = uids_for_file(path)
    with pytest.raises(ValueError, match="unlabelled"):
        cc.labels_in_file_order(path, {u: "none" for u in uids[1:]})
    with pytest.raises(ValueError, match="other predictions"):
        extra = {**{u: "none" for u in uids}, "pred-0000000000000000": "none"}
        cc.labels_in_file_order(path, extra)
