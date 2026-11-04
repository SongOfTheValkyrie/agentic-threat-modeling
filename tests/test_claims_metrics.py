"""Claim-level scoring (CLAIM_SCORING.md): CP, UFP, recall bounds, key scores, κ, repeat sample.

Uses the frozen cause lists of GT V2.0 and synthetic claims. No model output is read.
"""

import importlib.util
import itertools
import json
from dataclasses import replace
from pathlib import Path

import pytest

from src.evaluation import claims as cl
from src.evaluation.claims import Claim, status
from src.models.threat import StrideCategory, Threat

ROOT = Path(__file__).resolve().parents[1]
LISTS = ROOT / "benchmark_v2" / "v2.0"


def causes_of(architecture: str) -> cl.CauseSet:
    return cl.CauseSet.from_draft(json.loads((LISTS / f"{architecture}.causes.json").read_text()))


MTS = causes_of("multi_tenant_saas")
CIP = causes_of("cloud_ingest_pipeline")
R = "reasoned"  # a rationale text


def C(uid, no, label, unsure=False, cand="", plausible=(), rationale="", evidence=(),
      reason=""):
    return Claim(pred_uid=uid, claim_no=no, label=label, unsure=unsure, candidate_id=cand,
                 plausible_causes=tuple(plausible), rationale=rationale,
                 evidence_refs=tuple(evidence), reason_code=reason)


def example_a() -> list[Claim]:
    ev = ("components.object_store.config.per_tenant_prefix_enforced",)
    return [
        C("x1", 1, "MTS-04"),
        C("x2", 1, "MTS-04"),
        C("x3", 1, "MTS-01", rationale=R), C("x3", 2, "unsupported", rationale=R,
                                              reason="insufficient_evidence"),
        C("x4", 1, "unsupported", reason="generic_claim"),
        C("x5", 1, "pending_review", plausible=("MTS-03", "MTS-05"), evidence=ev,
          rationale="MTS-03 or MTS-05: ownership versus prefix"),
        C("x6", 1, "MTS-02", unsure=True, rationale=R),
        C("x7", 1, "valid_additional", cand="tls-version", rationale=R),
        C("x8", 1, "valid_additional", cand="tls-version", rationale=R),
        C("x9", 1, "MTS-04", unsure=True, rationale=R),
        C("x10", 1, "pending_review", rationale=R),
        C("x11", 1, "MTS-06", rationale=R), C("x11", 2, "MTS-05", rationale=R),
    ]


# --- statuses ----------------------------------------------------------------------------


@pytest.mark.parametrize("label, unsure, expected", [
    ("MTS-01", False, "M"), ("MTS-01", True, "P"),
    ("valid_additional", False, "V"), ("valid_additional", True, "P"),
    ("unsupported", False, "U"), ("unsupported", True, "P"),
    ("pending_review", False, "P"), ("pending_review", True, "P"),
])
def test_effective_status(label, unsure, expected):
    assert status(C("p", 1, label, unsure=unsure), MTS) == expected


def test_an_unknown_label_is_rejected():
    for bad in ("CIP-01", "MTS-X1", "none"):
        with pytest.raises(ValueError, match="unknown label"):
            status(C("p", 1, bad), MTS)


# --- Example A: Claim Precision, Unique-Finding Precision, recall ------------------------


def test_example_a_claim_precision_counts_every_claim_row():
    cp = cl.claim_precision(example_a(), MTS)
    assert (cp["g"], cp["v"], cp["p"], cp["u"], cp["n"]) == (5, 2, 4, 2, 13)
    assert cp["lower"] == pytest.approx(7 / 13) and cp["upper"] == pytest.approx(11 / 13)
    assert round(cp["lower"], 3) == 0.538 and round(cp["upper"], 3) == 0.846


def test_example_a_unique_finding_precision_deduplicates_but_keeps_unsure_visible():
    ufp = cl.unique_finding_precision(example_a(), MTS)
    # x9 (unsure, MTS-04) is NOT absorbed by the sure MTS-04: it stays a pending finding.
    assert (ufp["g"], ufp["v"], ufp["p"], ufp["u"], ufp["n"]) == (4, 1, 4, 2, 11)
    assert ufp["lower"] == pytest.approx(5 / 11) and ufp["upper"] == pytest.approx(9 / 11)
    assert round(ufp["lower"], 3) == 0.455 and round(ufp["upper"], 3) == 0.818


def test_example_a_recall_bounds_use_a_matching_and_absorb_only_here():
    recall = cl.cause_recall(example_a(), MTS)
    assert recall["found"] == ["MTS-01", "MTS-04", "MTS-05", "MTS-06"]
    for name in ("threat_cause_recall", "security_control_gap_recall"):
        r = recall[name]
        assert r["found_sure"] == 4 and r["denominator"] == 6
        # x5 can only add MTS-03 (MTS-05 is found); x6 adds MTS-02; x9 adds nothing; x10 nothing.
        assert r["upper_numerator"] == 6
        assert r["lower"] == pytest.approx(4 / 6) and r["upper"] == pytest.approx(1.0)


def test_example_a_prediction_classes():
    assert cl.prediction_classes(example_a(), MTS) == {
        "clean": 5, "pending": 4, "mixed": 1, "wrong": 1,
    }


# --- Example B: CP and UFP are different metrics -----------------------------------------


def _run(spec: dict) -> list[Claim]:
    return [C(uid, 1, label) for uid, label in spec.items()]


def test_example_b_the_two_precisions_differ_only_through_repetition():
    x = _run({"x1": "MTS-04", "x2": "MTS-04", "x3": "MTS-04", "x4": "MTS-04",
              "x5": "MTS-01", "x6": "unsupported"})
    y = _run({"y1": "MTS-04", "y2": "MTS-01", "y3": "unsupported"})
    z = _run({"z1": "MTS-04", "z2": "MTS-04", "z3": "MTS-04",
              "z4": "unsupported", "z5": "unsupported", "z6": "unsupported"})
    cp = {k: cl.claim_precision(v, MTS)["lower"] for k, v in (("x", x), ("y", y), ("z", z))}
    runs = (("x", x), ("y", y), ("z", z))
    ufp = {k: cl.unique_finding_precision(v, MTS)["lower"] for k, v in runs}
    assert cp == {"x": pytest.approx(5 / 6), "y": pytest.approx(2 / 3), "z": pytest.approx(0.5)}
    assert ufp == {"x": pytest.approx(2 / 3), "y": pytest.approx(2 / 3), "z": pytest.approx(0.25)}
    assert cl.unique_finding_precision(z, MTS)["n"] == 4  # unsupported claims are never merged


def test_precision_is_undefined_not_zero_without_claims():
    assert cl.claim_precision([], MTS)["lower"] is None
    assert cl.unique_finding_precision([], MTS)["upper"] is None


def test_candidate_ids_collapse_valid_additional_but_never_unsupported_claims():
    claims = [C("a", 1, "valid_additional", cand="k"), C("b", 1, "valid_additional", cand="k"),
              C("c", 1, "valid_additional"), C("d", 1, "valid_additional"),
              C("e", 1, "unsupported", cand="same", reason="generic_claim"),
              C("f", 1, "unsupported", cand="same", reason="generic_claim")]
    ufp = cl.unique_finding_precision(claims, MTS)
    assert (ufp["v"], ufp["u"]) == (3, 2)
    assert cl.claim_precision(claims, MTS)["v"] == 4


# --- bounds hold for every way of resolving the pending claims ---------------------------


def _resolutions(claims: list[Claim], causes: cl.CauseSet):
    pending = [i for i, c in enumerate(claims) if status(c, causes) == "P"]
    for choice in itertools.product(("correct", "unsupported"), repeat=len(pending)):
        resolved = list(claims)
        for index, outcome in zip(pending, choice, strict=True):
            claim = claims[index]
            if outcome == "unsupported":
                resolved[index] = replace(claim, label="unsupported", unsure=False,
                                          reason_code="insufficient_evidence")
            elif claim.label in causes.refs:
                resolved[index] = replace(claim, unsure=False)  # the cause is confirmed
            else:
                resolved[index] = replace(claim, label="valid_additional", unsure=False,
                                          candidate_id=f"new-{index}")
        yield resolved


def test_the_final_values_always_lie_within_the_bounds():
    claims = example_a()
    cp, ufp = cl.claim_precision(claims, MTS), cl.unique_finding_precision(claims, MTS)
    for resolved in _resolutions(claims, MTS):
        for bounds, metric in ((cp, cl.claim_precision), (ufp, cl.unique_finding_precision)):
            final = metric(resolved, MTS)
            assert final["p"] == 0
            assert bounds["lower"] - 1e-12 <= final["lower"] <= bounds["upper"] + 1e-12
            assert final["lower"] == final["upper"]


# --- recall details ----------------------------------------------------------------------


def test_a_claim_with_two_alternatives_adds_at_most_one_cause():
    ev = ("components.api.config.authentication",)
    pending = C("p", 1, "pending_review", plausible=("MTS-03", "MTS-05"), evidence=ev,
                rationale="MTS-03 and MTS-05")
    r = cl.cause_recall([pending], MTS)["threat_cause_recall"]
    assert (r["found_sure"], r["upper_numerator"]) == (0, 1)


def test_two_claims_for_one_cause_add_it_once_and_the_matching_uses_both_options():
    ev = ("components.api.config.authentication",)
    same = [C("p", 1, "pending_review", plausible=("MTS-03",), evidence=ev, rationale="MTS-03"),
            C("q", 1, "pending_review", plausible=("MTS-03",), evidence=ev, rationale="MTS-03")]
    assert cl.cause_recall(same, MTS)["threat_cause_recall"]["upper_numerator"] == 1
    flexible = [C("p", 1, "pending_review", plausible=("MTS-03", "MTS-05"), evidence=ev,
                  rationale="MTS-03 MTS-05"),
                C("q", 1, "pending_review", plausible=("MTS-03",), evidence=ev, rationale="MTS-03")]
    # A greedy choice of MTS-03 for p would block q; the maximum matching finds 2.
    assert cl.cause_recall(flexible, MTS)["threat_cause_recall"]["upper_numerator"] == 2


@pytest.mark.parametrize("claim", [
    C("p", 1, "pending_review", plausible=("MTS-03",), evidence=("a.b",), rationale=""),
    C("p", 1, "pending_review", plausible=("MTS-03",), evidence=("a.b",), rationale="no ref"),
    C("p", 1, "pending_review", plausible=("MTS-03",), evidence=(), rationale="MTS-03"),
    C("p", 1, "pending_review", plausible=("CIP-01",), evidence=("a.b",), rationale="CIP-01"),
    C("p", 1, "MTS-03", unsure=True, rationale=""),
    C("p", 1, "unsupported", reason="generic_claim"),
    C("p", 1, "valid_additional", cand="k", rationale=R),
])
def test_unjustified_or_irrelevant_claims_never_raise_the_recall(claim):
    r = cl.cause_recall([claim], MTS)["threat_cause_recall"]
    assert r["upper_numerator"] == r["found_sure"] == 0


def test_an_unsure_cause_with_a_rationale_counts_in_the_upper_bound_only():
    r = cl.cause_recall([C("p", 1, "MTS-03", unsure=True, rationale=R)], MTS)["threat_cause_recall"]
    assert (r["lower"], r["upper"]) == (0.0, pytest.approx(1 / 6))


def test_valid_additional_and_unsupported_never_change_recall():
    base = cl.cause_recall([C("a", 1, "MTS-01")], MTS)
    more = cl.cause_recall([C("a", 1, "MTS-01"), C("b", 1, "valid_additional", cand="k"),
                            C("c", 1, "unsupported", reason="generic_claim")], MTS)
    assert base == more


def test_control_gaps_count_in_the_gap_recall_but_not_in_the_threat_recall():
    recall = cl.cause_recall([C("p", 1, "CIP-04"), C("q", 1, "CIP-11"), C("r", 1, "CIP-02")], CIP)
    assert recall["threat_cause_recall"]["found_sure"] == 1
    assert recall["security_control_gap_recall"]["found_sure"] == 3
    assert (recall["threat_cause_recall"]["denominator"],
            recall["security_control_gap_recall"]["denominator"]) == (9, 11)


def test_control_gap_claims_are_correct_findings_in_both_precisions():
    claims = [C("p", 1, "CIP-04"), C("q", 1, "CIP-11"), C("r", 1, "unsupported",
                                                           reason="generic_claim")]
    assert cl.claim_precision(claims, CIP)["lower"] == pytest.approx(2 / 3)
    assert cl.unique_finding_precision(claims, CIP)["lower"] == pytest.approx(2 / 3)


# --- Example D: key scores, claim-level exclusion ----------------------------------------


def _record(target, category, text="x"):
    return {"id": f"m-{target}-{category}", "target": target, "target_kind": "component",
            "category": category, "description": text, "mitigation": "m"}


def _v1_ground_truth():
    def gt(target, category):
        return Threat(id=f"{target}:{category.value}", component_id=target, category=category,
                      description="v1", mitigation="v1")
    return [gt("monitoring", StrideCategory.REPUDIATION),
            gt("raw_bucket", StrideCategory.INFORMATION_DISCLOSURE),
            gt("ingest_api", StrideCategory.DENIAL_OF_SERVICE)]


def test_example_d_control_gap_claims_are_removed_before_keys_are_formed():
    predictions = {
        "p1": _record("monitoring", "repudiation"),
        "p2": _record("raw_bucket", "tampering"),
        "p3": _record("raw_bucket", "information_disclosure"),
        "p4": _record("monitoring", "repudiation"),
    }
    claims = [C("p1", 1, "CIP-11"),
              C("p2", 1, "CIP-04"), C("p2", 2, "unsupported", rationale=R,
                                       reason="insufficient_evidence"),
              C("p3", 1, "CIP-02"),
              C("p4", 1, "CIP-11", unsure=True, rationale=R)]
    scores = cl.key_scores(predictions, claims, CIP, _v1_ground_truth())
    assert scores["excluded_predictions"] == 1
    assert scores["removed_control_gap_claims"] == 2
    adjusted = scores["v2_adjusted_key_score"]
    assert adjusted["tp_keys"] == ["monitoring:repudiation", "raw_bucket:information_disclosure"]
    assert adjusted["fp_keys"] == ["raw_bucket:tampering"]
    v1 = scores["v1_key_score"]
    assert v1["tp_keys"] == ["monitoring:repudiation", "raw_bucket:information_disclosure"]
    assert v1["fp_keys"] == ["raw_bucket:tampering"]
    assert scores["v2_key_denominator"] == 8


def test_a_prediction_with_only_a_control_gap_claim_forms_no_key():
    predictions = {"p": _record("monitoring", "repudiation")}
    scores = cl.key_scores(predictions, [C("p", 1, "CIP-11")], CIP, _v1_ground_truth())
    adjusted = scores["v2_adjusted_key_score"]
    assert (adjusted["tp"], adjusted["fp"]) == (0, 0)
    assert "monitoring:repudiation" in adjusted["fn_keys"], "CIP-10's key is not credited"
    assert "monitoring:repudiation" in scores["v1_key_score"]["tp_keys"]


def test_a_control_gap_claim_with_a_threat_cause_keeps_the_prediction():
    predictions = {"p": _record("monitoring", "repudiation")}
    claims = [C("p", 1, "CIP-11", rationale=R), C("p", 2, "CIP-10", rationale=R)]
    scores = cl.key_scores(predictions, claims, CIP, _v1_ground_truth())
    assert scores["excluded_predictions"] == 0
    assert scores["v2_adjusted_key_score"]["tp_keys"] == ["monitoring:repudiation"]
    assert scores["removed_control_gap_claims"] == 1


def test_unmatched_and_unsupported_predictions_are_never_excluded():
    predictions = {"a": _record("ingest_api", "spoofing"), "b": _record("warehouse", "tampering")}
    claims = [C("a", 1, "unsupported", reason="generic_claim"), C("b", 1, "pending_review",
                                                                   rationale=R)]
    scores = cl.key_scores(predictions, claims, CIP, _v1_ground_truth())
    assert scores["excluded_predictions"] == 0
    assert scores["v2_adjusted_key_score"]["fp"] == 2


def test_the_v1_evaluator_function_is_the_unchanged_one():
    from src.evaluation import evaluator
    assert cl.evaluate is evaluator.evaluate


def test_key_scores_need_a_claim_for_every_prediction():
    with pytest.raises(ValueError, match="no claim"):
        cl.key_scores({"p": _record("a", "spoofing")}, [], CIP, _v1_ground_truth())


def test_derived_judgements_never_block_and_follow_the_frozen_cause():
    assert cl.derived_judgements({"target": "shared_db", "category": "tampering"},
                                 "MTS-04", MTS) == {"target": "ok", "stride": "ok"}
    assert cl.derived_judgements({"target": "api", "category": "spoofing"},
                                 "MTS-04", MTS) == {"target": "deviates", "stride": "deviates"}
    assert cl.derived_judgements({"target": "raw_bucket", "category": "tampering"},
                                 "CIP-04", CIP) == {"target": "ok", "stride": "n/a"}


# --- Example C: κ and exact set agreement ------------------------------------------------


def _passes():
    p1 = [["MTS-04"], ["MTS-01", "unsupported"], ["unsupported"], ["MTS-03"], ["MTS-03"],
          ["unsupported"], ["MTS-05", "MTS-06"], ["valid_additional"], ["unsupported"]]
    p2 = [["MTS-04"], ["MTS-01"], ["unsupported"], ["pending_review"], ["MTS-03"],
          ["unsupported"], ["MTS-05", "MTS-06"], ["unsupported"], ["MTS-02"]]
    def claims(passes, unsure_item=None):
        return [C(f"i{i}", n, label, unsure=(i == unsure_item))
                for i, labels in enumerate(passes, 1) for n, label in enumerate(labels, 1)]
    return claims(p1), claims(p2, unsure_item=9)


def test_example_c_pair_kappa_and_exact_set_agreement():
    first, second = _passes()
    result = cl.reliability(first, second, MTS.labels())
    counts = (result["items_total"], result["items_used"], result["items_excluded_unsure"])
    assert counts == (9, 8, 1)
    assert (result["a"], result["b"], result["c"], result["d"]) == (7, 3, 2, 60)
    assert result["pairs"] == 72
    assert result["kappa"] == pytest.approx(0.6970, abs=1e-4)
    assert result["exact_set_agreement"] == pytest.approx(0.625)
    assert result["positive_agreement"] == pytest.approx(14 / 19)
    assert result["excluded_share"] == pytest.approx(1 / 9)
    assert len(result["disagreements"]) == 3
    assert result["per_label"]["MTS-03"] == {"both": 1, "pass1_only": 1, "pass2_only": 0}


def test_identical_passes_give_kappa_one_and_the_universe_is_fixed_by_the_architecture():
    first, _ = _passes()
    same = [replace(c, unsure=False) for c in first]
    result = cl.reliability(same, same, MTS.labels())
    assert result["kappa"] == pytest.approx(1.0) and result["exact_set_agreement"] == 1.0
    assert len(MTS.labels()) == 9 and len(CIP.labels()) == 14
    with pytest.raises(ValueError, match="outside the universe"):
        cl.reliability(same, same, ["MTS-01"])


def test_kappa_is_undefined_when_chance_agreement_is_one():
    one = [C("a", 1, "x"), C("b", 1, "x")]
    result = cl.reliability(one, one, ["x"])
    assert result["kappa"] is None and result["exact_set_agreement"] == 1.0


def test_passes_over_different_predictions_are_rejected():
    with pytest.raises(ValueError, match="different predictions"):
        cl.reliability([C("a", 1, "MTS-01")], [C("b", 1, "MTS-01")], MTS.labels())


# --- repeat sample -----------------------------------------------------------------------


def _first_pass(n=60):
    labels = (["MTS-01"] * 28 + ["unsupported"] * 18 + ["valid_additional"] * 4)[:n - 10]
    labels += ["pending_review"] * 6 + ["MTS-02"] * 4
    claims = []
    for i, label in enumerate(labels[:n]):
        claims.append(C(f"u{i:02d}", 1, label, unsure=(label == "MTS-02"), rationale=R,
                        reason="generic_claim" if label == "unsupported" else ""))
    return claims


def test_the_repeat_sample_is_reproducible_stratified_and_without_development_cases():
    first = _first_pass()
    dev = {f"u{i:02d}" for i in range(12)}
    a = cl.repeat_sample(first, MTS, dev, seed=1, first_pass_finished="2026-11-05T10:00:00")
    b = cl.repeat_sample(first, MTS, dev, seed=1, first_pass_finished="2026-11-05T10:00:00")
    c = cl.repeat_sample(first, MTS, dev, seed=2, first_pass_finished="2026-11-05T10:00:00")
    assert a == b and a["selected"] != c["selected"]
    assert len(a["selected"]) == 20 and len(set(a["selected"])) == 20
    assert not dev & set(a["selected"])
    assert a["excluded_development_cases"] == 12 and a["eligible"] == 48
    assert all(n >= 4 for n in a["strata_selected"].values())
    assert sum(a["strata_selected"].values()) == 20
    assert a["not_before"] == "2026-11-06T10:00:00"


def test_a_small_phase_takes_everything_eligible_and_an_unlabelled_pass_is_refused():
    few = [C(f"s{i}", 1, "MTS-01") for i in range(7)]
    sample = cl.repeat_sample(few, MTS, set(), 1, "2026-11-05T10:00:00", size=20)
    assert len(sample["selected"]) == 7
    with pytest.raises(ValueError, match="unlabelled"):
        cl.repeat_sample([C("s", 1, "")], MTS, set(), 1, "2026-11-05T10:00:00")


# --- compatibility with the single-label code of the first release -----------------------


def _legacy():
    spec = importlib.util.spec_from_file_location(
        "check_cause_consistency", ROOT / "scripts" / "check_cause_consistency.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_for_single_claim_sure_data_the_new_counts_equal_the_old_ones():
    cc = _legacy()
    draft = cc.load_drafts()["multi_tenant_saas"]
    labels = ["MTS-01", "MTS-02", "unsupported", "valid_additional", "pending_review"]
    claims = [C(f"p{i}", 1, label) for i, label in enumerate(labels)]
    old = cc.cause_claim_counts(draft, labels)
    ufp = cl.unique_finding_precision(claims, MTS)
    assert (old["mapped"], old["valid_additional"], old["pending_review"], old["unsupported"]) == (
        ufp["g"], ufp["v"], ufp["p"], ufp["u"])
    assert old["precision_lower"] == pytest.approx(ufp["lower"])
    assert old["precision_upper"] == pytest.approx(ufp["upper"])
    assert cl.claim_precision(claims, MTS)["lower"] == pytest.approx(ufp["lower"])
    new_recall = cl.cause_recall(claims, MTS)["threat_cause_recall"]
    old_recall = cc.recall_from_labels(draft, labels)["threat_cause_recall"]
    assert (new_recall["found_sure"], new_recall["denominator"]) == old_recall


def test_the_documented_differences_to_the_first_release():
    """An unsure row is pending whatever its label (old code looked at the label only)."""
    cc = _legacy()
    draft = cc.load_drafts()["multi_tenant_saas"]
    old = cc.cause_claim_counts(draft, ["MTS-01"])
    assert old["mapped"] == 1 and old["pending_review"] == 0
    new = cl.unique_finding_precision([C("p", 1, "MTS-01", unsure=True, rationale=R)], MTS)
    assert (new["g"], new["p"]) == (0, 1)
