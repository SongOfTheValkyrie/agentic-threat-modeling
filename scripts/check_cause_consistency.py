#!/usr/bin/env python3
"""Consistency check of the frozen V2 cause lists (gate G2 passed).

Answers three questions, offline and without any model output:

1. Do the two recall denominators match? Threat Cause Recall is taken over the
   STRIDE-mapped causes, Security Control Gap Recall over all causes. The sets
   declared in each draft (``recall_sets``) must equal the sets derived from the
   cause fields, and nothing else (boundary cases, unsupported items, candidate
   chains) may be in them.
2. Are the STRIDE mappings unambiguous? Rules per cause (0 categories exactly
   for causes without STRIDE mapping, at most 2, no duplicates, valid names) and
   an inventory of where the coarse ``(target, STRIDE)`` key cannot tell causes
   apart. Those overlaps are reported, not hidden.
3. Can both metrics be computed from the same stored predictions? The reference
   functions below take a stored prediction file plus one label per prediction
   and return both recalls from that single label set.

Usage (from the repository root)::

    python scripts/check_cause_consistency.py          # print the report, exit 1 on failures
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation.evaluator import evaluate  # noqa: E402
from src.evaluation.prediction_ids import assert_unique, prediction_uids  # noqa: E402
from src.evaluation.predictions import read_predictions  # noqa: E402
from src.models.threat import StrideCategory, Threat  # noqa: E402

LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
STRIDE = {
    "spoofing", "tampering", "repudiation", "information_disclosure",
    "denial_of_service", "elevation_of_privilege",
}
MAX_CATEGORIES = 2
NON_CAUSE_LABELS = {"none", "unsure", "new_cause_proposed"}


def load_drafts(directory: Path = LISTS_DIR) -> dict[str, dict]:
    drafts = {}
    for path in sorted(directory.glob("*.causes.json")):
        draft = json.loads(path.read_text())
        drafts[draft["architecture_id"]] = draft
    return drafts


def derived_recall_sets(draft: dict) -> dict[str, list[str]]:
    """The two denominators, derived from the cause fields alone."""
    return {
        "threat_cause_recall": [
            c["ref"] for c in draft["causes"] if c["risk_class"] == "stride_threat"
        ],
        "security_control_gap_recall": [c["ref"] for c in draft["causes"]],
    }


# --- 1. denominators ---------------------------------------------------------------


def check_denominators(drafts: dict[str, dict]) -> tuple[list[str], dict]:
    failures: list[str] = []
    numbers: dict = {"per_architecture": {}, "pooled": {}}
    all_refs: list[str] = []
    for name, draft in drafts.items():
        derived = derived_recall_sets(draft)
        declared = draft.get("recall_sets", {})
        for metric, refs in derived.items():
            listed = declared.get(metric)
            if listed is None:
                failures.append(f"{name}: recall_sets.{metric} is missing")
            elif len(set(listed)) != len(listed):
                failures.append(f"{name}: recall_sets.{metric} contains duplicates")
            elif sorted(listed) != sorted(refs):
                failures.append(
                    f"{name}: recall_sets.{metric} differs from the sets derived from the "
                    f"causes (declared {sorted(listed)}, derived {sorted(refs)})"
                )
        threat = set(derived["threat_cause_recall"])
        gap = set(derived["security_control_gap_recall"])
        if not threat <= gap:
            failures.append(f"{name}: threat causes are not a subset of all causes")
        # Causes outside the threat set are exactly those without STRIDE categories.
        no_stride = {c["ref"] for c in draft["causes"] if not c["categories"]}
        if gap - threat != no_stride:
            failures.append(
                f"{name}: causes outside the threat set differ from those without STRIDE"
            )
        # Nothing else may leak into a denominator.
        others = (
            {b["ref"] for b in draft["boundary_cases"]}
            | {u["ref"] for u in draft["unsupported"]}
            | {x["ref"] for x in draft["candidate_chain_causes"]}
        )
        if (threat | gap) & others:
            failures.append(
                f"{name}: boundary, unsupported or chain refs in a denominator: "
                f"{sorted((threat | gap) & others)}"
            )
        all_refs += [c["ref"] for c in draft["causes"]] + sorted(others)
        numbers["per_architecture"][name] = {
            "threat_cause_recall_denominator": len(threat),
            "security_control_gap_recall_denominator": len(gap),
            "control_gap_only": sorted(gap - threat),
        }
    if len(set(all_refs)) != len(all_refs):
        failures.append("refs are not unique across the two architectures")
    per = numbers["per_architecture"].values()
    numbers["pooled"] = {
        "threat_cause_recall_denominator": sum(
            p["threat_cause_recall_denominator"] for p in per
        ),
        "security_control_gap_recall_denominator": sum(
            p["security_control_gap_recall_denominator"] for p in per
        ),
    }
    return failures, numbers


# --- 2. STRIDE mapping --------------------------------------------------------------


def _expand(entry: dict) -> list[str]:
    return [f"{t}:{entry['category']}" for t in entry["targets"]]


def check_stride_mapping(drafts: dict[str, dict]) -> tuple[list[str], dict]:
    failures: list[str] = []
    info: dict = {
        "shared_keys": {},
        "excluded_entries_sharing_a_confirmed_key": [],
        "control_gap_targets_with_stride_keys": [],
        "coarse_mappings": [],
        "entries": 0,
        "distinct_keys": 0,
    }
    for draft in drafts.values():
        key_causes: dict[str, list[str]] = {}
        for cause in draft["causes"]:
            ref = cause["ref"]
            categories = [k["category"] for k in cause["categories"]]
            if cause["stride_scored"] != bool(categories):
                failures.append(f"{ref}: stride_scored disagrees with its categories")
            if cause["risk_class"] == "stride_threat" and not categories:
                failures.append(f"{ref}: a threat cause needs at least one STRIDE category")
            if cause["risk_class"] != "stride_threat" and categories:
                failures.append(f"{ref}: a control gap must not carry STRIDE categories")
            if len(categories) > MAX_CATEGORIES:
                failures.append(f"{ref}: more than {MAX_CATEGORIES} categories")
            if len(set(categories)) != len(categories):
                failures.append(f"{ref}: duplicate category")
            if not set(categories) <= STRIDE:
                failures.append(f"{ref}: unknown category in {categories}")
            for category in categories:
                key_causes.setdefault(f"{cause['target']}:{category}", []).append(ref)
            if cause.get("stride_mapping_note"):
                info["coarse_mappings"].append(ref)
        info["entries"] += sum(len(v) for v in key_causes.values())
        info["distinct_keys"] += len(key_causes)
        info["shared_keys"].update({k: v for k, v in key_causes.items() if len(v) > 1})

        for section, kind in (("unsupported", "unsupported"), ("boundary_cases", "boundary")):
            for entry in draft[section]:
                for key in _expand(entry):
                    if key in key_causes:
                        info["excluded_entries_sharing_a_confirmed_key"].append(
                            (entry["ref"], kind, key, key_causes[key])
                        )
        stride_targets = {k.split(":")[0]: k for k in key_causes}
        for cause in draft["causes"]:
            if not cause["categories"] and cause["target"] in stride_targets:
                shared = sorted(k for k in key_causes if k.split(":")[0] == cause["target"])
                info["control_gap_targets_with_stride_keys"].append((cause["ref"], shared))
    return failures, info


# --- 3. both recalls from the same stored predictions --------------------------------


def recall_from_labels(draft: dict, labels: list[str]) -> dict:
    """Both cause recalls from one label per prediction.

    ``labels`` has one entry per prediction in file order: a cause ref of this
    architecture, or ``none`` / ``unsure`` / ``new_cause_proposed``. Several
    predictions with the same cause collapse into one found cause. Candidate
    chain refs are not valid labels, because chains are excluded from both metrics.
    """
    sets = derived_recall_sets(draft)
    valid = set(sets["security_control_gap_recall"])
    unknown = sorted(set(labels) - valid - NON_CAUSE_LABELS)
    if unknown:
        raise ValueError(f"labels that are no cause of {draft['architecture_id']}: {unknown}")
    found = {label for label in labels if label in valid}
    threat = set(sets["threat_cause_recall"])
    return {
        "found": sorted(found),
        "threat_cause_recall": (len(found & threat), len(threat)),
        "security_control_gap_recall": (len(found), len(valid)),
        "found_control_gap_only": sorted(found - threat),
    }


def score_prediction_file(path: str | Path, labels: list[str], draft: dict) -> dict:
    """Read one stored prediction file and compute both recalls from the labels."""
    record = read_predictions(path)
    if record["architecture"] != draft["architecture_id"]:
        raise ValueError(
            f"{path} is a run on {record['architecture']}, not {draft['architecture_id']}"
        )
    if len(labels) != record["num_predictions"] or len(labels) != len(record["predictions"]):
        raise ValueError(
            f"{len(labels)} labels for {record['num_predictions']} stored predictions"
        )
    result = recall_from_labels(draft, labels)
    result["predictions"] = len(labels)
    return result


def labels_in_file_order(path: str | Path, labels_by_uid: dict[str, str]) -> list[str]:
    """Join annotation labels, keyed by stable prediction identifier, to a stored file.

    Every prediction of the file needs a label and every label must belong to the
    file, so a stale or partial annotation cannot be scored by accident.
    """
    uids = prediction_uids(read_predictions(path))
    assert_unique(uids)
    missing = [u for u in uids if u not in labels_by_uid]
    unknown = sorted(set(labels_by_uid) - set(uids))
    if missing or unknown:
        raise ValueError(
            f"labels do not match the file: {len(missing)} prediction(s) unlabelled, "
            f"{len(unknown)} label(s) for other predictions"
        )
    return [labels_by_uid[u] for u in uids]


# --- coarse (target, STRIDE) metrics and cause claims (decision D23) -------------------


def control_gap_refs(draft: dict) -> set[str]:
    """Causes without a STRIDE mapping: CIP-04 and CIP-11 in the current drafts."""
    return {c["ref"] for c in draft["causes"] if c["risk_class"] != "stride_threat"}


def _threats_from_records(predictions: list[dict]) -> list[Threat]:
    return [
        Threat(
            id=p.get("id", f"p{i}"),
            component_id=p["target"] if p.get("target_kind", "component") == "component" else None,
            data_flow_id=p["target"] if p.get("target_kind") == "data_flow" else None,
            category=StrideCategory(p["category"]),
            description=p["description"],
            mitigation=p["mitigation"],
        )
        for i, p in enumerate(predictions)
    ]


def v2_key_ground_truth(draft: dict) -> list[Threat]:
    """The (target, STRIDE) keys of the STRIDE-mapped causes, as the V1 evaluator expects."""
    return [
        Threat(
            id=f"{c['ref']}:{k['category']}",
            component_id=c["target"] if c["target_kind"] == "component" else None,
            data_flow_id=c["target"] if c["target_kind"] == "data_flow" else None,
            category=StrideCategory(k["category"]),
            description=k["scenario"],
            mitigation="",
        )
        for c in draft["causes"]
        for k in c["categories"]
    ]


def _summary(result) -> dict:
    return {
        "tp": result.true_positives, "fp": result.false_positives, "fn": result.false_negatives,
        "precision": result.precision, "recall": result.recall, "f1": result.f1,
        "tp_keys": result.true_positive_keys, "fp_keys": result.false_positive_keys,
        "fn_keys": result.false_negative_keys,
    }


def coarse_scores(
    draft: dict,
    predictions: list[dict],
    labels: list[str],
    v1_ground_truth: list[Threat],
) -> dict:
    """The two (target, STRIDE) scores on the same stored predictions.

    ``v1_key_score``: the unchanged V1 evaluator, all predictions, V1 ground truth.
    ``v2_coarse``: the same evaluator function on the V2 keys, with every prediction
    that the annotation mapped to a control-gap cause left out (neither TP nor FP).
    Predictions labelled ``none``, ``unsure``, ``new_cause_proposed`` or any other
    cause stay in, so unmatched and unsupported predictions remain part of precision.
    The two scores are different metrics and are never merged.
    """
    if len(labels) != len(predictions):
        raise ValueError(f"{len(labels)} labels for {len(predictions)} predictions")
    gaps = control_gap_refs(draft)
    kept = [p for p, label in zip(predictions, labels, strict=True) if label not in gaps]
    excluded = [p for p, label in zip(predictions, labels, strict=True) if label in gaps]
    v1 = evaluate(_threats_from_records(predictions), v1_ground_truth)
    v2 = evaluate(_threats_from_records(kept), v2_key_ground_truth(draft))
    return {
        "v1_key_score": _summary(v1),
        "v2_coarse": _summary(v2),
        "excluded_predictions": len(excluded),
        "excluded_keys": sorted({f"{p['target']}:{p['category']}" for p in excluded}),
        "scored_predictions": len(kept),
        "v2_key_denominator": len({f"{t.component_id or t.data_flow_id}:{t.category.value}"
                                   for t in v2_key_ground_truth(draft)}),
    }


def cause_claim_counts(draft: dict, labels: list[str]) -> dict:
    """Claim counts behind cause precision (V2_SPEC section 8), review not yet applied.

    ``mapped`` counts distinct causes, control gaps included (D23). Each ``none`` is
    an unsupported claim. ``unsure`` and ``new_cause_proposed`` are pending. A
    ``new_cause_proposed`` prediction counts as its own claim here; collapsing
    predictions that name the same candidate needs the annotation text and belongs
    to the scorer.
    """
    sets = derived_recall_sets(draft)
    valid = set(sets["security_control_gap_recall"])
    unknown = sorted(set(labels) - valid - NON_CAUSE_LABELS)
    if unknown:
        raise ValueError(f"labels that are no cause of {draft['architecture_id']}: {unknown}")
    mapped = {label for label in labels if label in valid}
    pending = sum(1 for label in labels if label in {"unsure", "new_cause_proposed"})
    unsupported = sum(1 for label in labels if label == "none")
    total = len(mapped) + pending + unsupported
    return {
        "mapped": len(mapped),
        "mapped_control_gaps": sorted(mapped & control_gap_refs(draft)),
        "pending_review": pending,
        "unsupported": unsupported,
        "precision_lower": len(mapped) / total if total else 0.0,
        "precision_upper": (len(mapped) + pending) / total if total else 0.0,
    }


# --- report -----------------------------------------------------------------------------


def report() -> int:
    drafts = load_drafts()
    failures, numbers = check_denominators(drafts)
    stride_failures, info = check_stride_mapping(drafts)
    failures += stride_failures

    print("1. Recall denominators")
    for name, n in numbers["per_architecture"].items():
        print(
            f"   {name}: Threat Cause Recall over {n['threat_cause_recall_denominator']}, "
            f"Security Control Gap Recall over {n['security_control_gap_recall_denominator']} "
            f"(control-gap-only: {', '.join(n['control_gap_only']) or 'none'})"
        )
    pooled = numbers["pooled"]
    print(
        f"   pooled: {pooled['threat_cause_recall_denominator']} and "
        f"{pooled['security_control_gap_recall_denominator']}"
    )

    print("2. STRIDE mapping")
    print(f"   {info['entries']} (target, STRIDE) entries, {info['distinct_keys']} distinct keys")
    if info["coarse_mappings"]:
        print(f"   coarse mappings (no claim of an escalation path): {info['coarse_mappings']}")
    for key, refs in sorted(info["shared_keys"].items()):
        print(f"   key {key} is shared by causes {refs}: the coarse metric cannot tell them apart")
    for ref, kind, key, refs in info["excluded_entries_sharing_a_confirmed_key"]:
        print(
            f"   {kind} {ref} shares key {key} with confirmed {refs}: "
            "only the cause label separates"
        )
    for ref, keys in info["control_gap_targets_with_stride_keys"]:
        print(f"   control gap {ref} has no key of its own; its target also carries {keys}")

    print("3. Both recalls from one label set: see tests/test_cause_consistency.py")
    if failures:
        print(f"\n{len(failures)} failure(s):")
        for failure in failures:
            print(f"  FAIL: {failure}")
        return 1
    print("\nConsistency checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(report())
