"""Claim-level scoring for the V2 annotation (V2_SPEC.md D27 to D32).

Normative definitions: ``benchmark_v2/annotation/CLAIM_SCORING.md``. This module only
computes; it never reads model output, never assigns a label and never touches the
frozen cause lists or the V1 evaluator (it calls ``evaluate`` unchanged).

Terms. A *claim* is one asserted root cause inside a prediction. Its label is a cause ref
of the architecture, or ``valid_additional``, ``unsupported`` or ``pending_review``. Its
*status* is M (sure cause), V (valid additional), P (pending) or U (unsupported).

Two precisions with two names, never merged:

* **Claim Precision (CP)**: on individual claims, no deduplication.
* **Unique-Finding Precision (UFP)**: on deduplicated findings; unsupported claims are
  never merged.

Both are reported as lower and upper bounds while claims are pending.
"""

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.evaluation.evaluator import evaluate
from src.models.threat import StrideCategory, Threat

VA = "valid_additional"
UN = "unsupported"
PR = "pending_review"
STATUS_LABELS = (VA, UN, PR)

M, V, P, U = "M", "V", "P", "U"

REASON_CODES = (
    "explicit_contradiction",
    "insufficient_evidence",
    "generic_claim",
    "wrong_mechanism",
    "out_of_scope",
    "other",
)


# --- causes ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class CauseSet:
    """The frozen causes of one architecture (read from a V2 cause list)."""

    architecture: str
    causes: dict  # ref -> cause dict
    threat: frozenset  # refs with a STRIDE mapping (stride_threat)
    gaps: frozenset  # control gaps

    @classmethod
    def from_draft(cls, draft: dict) -> "CauseSet":
        causes = {c["ref"]: c for c in draft["causes"]}
        threat = frozenset(r for r, c in causes.items() if c["risk_class"] == "stride_threat")
        return cls(
            architecture=draft["architecture_id"],
            causes=causes,
            threat=threat,
            gaps=frozenset(causes) - threat,
        )

    @property
    def refs(self) -> frozenset:
        return frozenset(self.causes)

    def labels(self) -> list[str]:
        """The label universe: causes in list order, then the three status labels."""
        return list(self.causes) + list(STATUS_LABELS)

    def keys(self) -> set[tuple[str, str]]:
        """The V2 (target, category) keys of the threat causes."""
        return {
            (c["target"], k["category"])
            for ref, c in self.causes.items() if ref in self.threat for k in c["categories"]
        }


# --- claims and statuses ---------------------------------------------------------------------


@dataclass(frozen=True)
class Claim:
    pred_uid: str
    claim_no: int
    label: str
    unsure: bool = False
    candidate_id: str = ""
    plausible_causes: tuple = ()
    rationale: str = ""
    evidence_refs: tuple = ()
    reason_code: str = ""
    claim_text: str = ""
    extra: dict = field(default_factory=dict, compare=False, hash=False)


def status(claim: Claim, causes: CauseSet) -> str:
    """Effective status. An unsure claim is pending whatever its label."""
    if claim.unsure or claim.label == PR:
        return P
    if claim.label in causes.refs:
        return M
    if claim.label == VA:
        return V
    if claim.label == UN:
        return U
    raise ValueError(f"unknown label {claim.label!r} for {causes.architecture}")


def _ratio(numerator: int, denominator: int):
    return numerator / denominator if denominator else None


# --- Claim Precision -------------------------------------------------------------------------


def claim_precision(claims: list[Claim], causes: CauseSet) -> dict:
    """CP: individual claim rows, no deduplication. ``None`` bounds mean undefined (n = 0)."""
    count = Counter(status(c, causes) for c in claims)
    g, v, p, u = count[M], count[V], count[P], count[U]
    n = g + v + p + u
    return {
        "metric": "claim_precision", "g": g, "v": v, "p": p, "u": u, "n": n,
        "lower": _ratio(g + v, n), "upper": _ratio(g + v + p, n),
    }


# --- Unique-Finding Precision --------------------------------------------------------------------


def unique_finding_precision(claims: list[Claim], causes: CauseSet) -> dict:
    """UFP: deduplicated findings; unsupported claims stay individual; no absorption.

    Sure causes and pending claims for the same cause are different findings, so an unsure
    claim never disappears because the cause is sure elsewhere.
    """
    sure_causes: set = set()
    valid: set = set()
    pending: set = set()
    unsupported = 0
    for claim in claims:
        st = status(claim, causes)
        row_identity = ("row", claim.pred_uid, claim.claim_no)
        if st == M:
            sure_causes.add(claim.label)
        elif st == V:
            valid.add(("cand", claim.candidate_id) if claim.candidate_id else row_identity)
        elif st == P:
            if claim.label in causes.refs:
                pending.add(("pending-cause", claim.label))
            elif claim.candidate_id:
                pending.add(("cand", claim.candidate_id))
            else:
                pending.add(row_identity)
        else:
            unsupported += 1
    g, v, p = len(sure_causes), len(valid), len(pending)
    n = g + v + p + unsupported
    return {
        "metric": "unique_finding_precision", "g": g, "v": v, "p": p, "u": unsupported, "n": n,
        "lower": _ratio(g + v, n), "upper": _ratio(g + v + p, n),
    }


# --- Cause recall ----------------------------------------------------------------------------


def _plausible(claim: Claim, causes: CauseSet) -> set:
    """Justified plausible causes of a pending claim (rule V11).

    The own cause label of an unsure claim counts if a rationale is given. A listed
    plausible cause counts only if the rationale names it and evidence paths are given.
    """
    plausible: set = set()
    if claim.rationale.strip():
        if claim.label in causes.refs:
            plausible.add(claim.label)
        if claim.evidence_refs:
            plausible |= {
                ref for ref in claim.plausible_causes
                if ref in causes.refs and ref in claim.rationale
            }
    return plausible


def _max_matching(edges: dict) -> int:
    """Size of a maximum bipartite matching; ``edges`` maps a claim key to a set of causes."""
    owner: dict = {}

    def augment(key, seen) -> bool:
        for cause in edges[key]:
            if cause in seen:
                continue
            seen.add(cause)
            if cause not in owner or augment(owner[cause], seen):
                owner[cause] = key
                return True
        return False

    return sum(1 for key in edges if augment(key, set()))


def cause_recall(claims: list[Claim], causes: CauseSet) -> dict:
    """Threat Cause Recall (S = threat causes) and Security Control Gap Recall (S = all)."""
    found = {
        c.label for c in claims if status(c, causes) == M
    }
    pending = [c for c in claims if status(c, causes) == P]
    result = {"metric": "cause_recall", "found": sorted(found)}
    for name, scope in (("threat_cause_recall", causes.threat),
                        ("security_control_gap_recall", causes.refs)):
        open_causes = scope - found
        edges = {}
        for claim in pending:
            options = _plausible(claim, causes) & open_causes
            if options:
                edges[(claim.pred_uid, claim.claim_no)] = options
        lower = len(found & scope)
        upper = lower + _max_matching(edges)
        result[name] = {
            "found_sure": lower, "upper_numerator": upper, "denominator": len(scope),
            "lower": _ratio(lower, len(scope)), "upper": _ratio(upper, len(scope)),
        }
    return result


# --- Prediction distribution (descriptive) ---------------------------------------------------


def prediction_classes(claims: list[Claim], causes: CauseSet) -> dict:
    """Counts of clean / pending / mixed / wrong predictions. Never a precision."""
    by_prediction: dict[str, Counter] = {}
    for claim in claims:
        by_prediction.setdefault(claim.pred_uid, Counter())[status(claim, causes)] += 1
    counts = Counter()
    for tally in by_prediction.values():
        m, p, u = tally[M] + tally[V], tally[P], tally[U]
        if u == 0:
            counts["clean" if p == 0 else "pending"] += 1
        else:
            counts["mixed" if m >= 1 else "wrong"] += 1
    return {name: counts[name] for name in ("clean", "pending", "mixed", "wrong")}


# --- Key scores ------------------------------------------------------------------------------


def threats_from_records(predictions: list[dict]) -> list[Threat]:
    """Stored prediction records as ``Threat`` objects for the unchanged V1 evaluator."""
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


def v2_key_ground_truth(causes: CauseSet) -> list[Threat]:
    """The (target, category) keys of the threat causes, as the V1 evaluator expects them."""
    threats = []
    for ref in causes.causes:
        if ref not in causes.threat:
            continue
        cause = causes.causes[ref]
        for entry in cause["categories"]:
            threats.append(Threat(
                id=f"{ref}:{entry['category']}",
                component_id=cause["target"] if cause["target_kind"] == "component" else None,
                data_flow_id=cause["target"] if cause["target_kind"] == "data_flow" else None,
                category=StrideCategory(entry["category"]),
                description=entry["scenario"],
                mitigation="",
            ))
    return threats


def _key_summary(result) -> dict:
    return {
        "tp": result.true_positives, "fp": result.false_positives, "fn": result.false_negatives,
        "precision": result.precision, "recall": result.recall, "f1": result.f1,
        "tp_keys": result.true_positive_keys, "fp_keys": result.false_positive_keys,
        "fn_keys": result.false_negative_keys,
    }


def key_scores(
    predictions: dict[str, dict],
    claims: list[Claim],
    causes: CauseSet,
    v1_ground_truth: list[Threat],
) -> dict:
    """The V1 key score and the V2 adjusted key score on the same predictions.

    ``predictions`` maps ``pred_uid`` to the stored prediction record. The V1 evaluator is
    called unchanged. For the adjusted score, sure control-gap claims are removed first;
    only predictions with a remaining claim form a key.
    """
    by_prediction: dict[str, list[Claim]] = {}
    for claim in claims:
        by_prediction.setdefault(claim.pred_uid, []).append(claim)
    missing = sorted(set(predictions) - set(by_prediction))
    if missing:
        raise ValueError(f"{len(missing)} predictions have no claim")

    def sure_gap(claim: Claim) -> bool:
        return status(claim, causes) == M and claim.label in causes.gaps

    kept, removed_claims = [], 0
    for uid, record in predictions.items():
        remaining = [c for c in by_prediction[uid] if not sure_gap(c)]
        removed_claims += len(by_prediction[uid]) - len(remaining)
        if remaining:
            kept.append(record)
    v1 = evaluate(threats_from_records(list(predictions.values())), v1_ground_truth)
    v2 = evaluate(threats_from_records(kept), v2_key_ground_truth(causes))
    return {
        "v1_key_score": _key_summary(v1),
        "v2_adjusted_key_score": _key_summary(v2),
        "excluded_predictions": len(predictions) - len(kept),
        "removed_control_gap_claims": removed_claims,
        "v2_key_denominator": len(causes.keys()),
    }


def derived_judgements(prediction: dict, cause_ref: str, causes: CauseSet) -> dict:
    """Target and STRIDE agreement of a prediction with a cause (descriptive, never blocking)."""
    cause = causes.causes[cause_ref]
    categories = [k["category"] for k in cause["categories"]]
    return {
        "target": "ok" if prediction["target"] == cause["target"] else "deviates",
        "stride": ("n/a" if not categories
                   else "ok" if prediction["category"] in categories else "deviates"),
    }


# --- Reliability -----------------------------------------------------------------------------


def label_sets(claims: list[Claim]) -> dict[str, frozenset]:
    """Per prediction: the set of claim labels (duplicates removed, order ignored)."""
    sets: dict[str, set] = {}
    for claim in claims:
        sets.setdefault(claim.pred_uid, set()).add(claim.label)
    return {uid: frozenset(labels) for uid, labels in sets.items()}


def unsure_items(claims: list[Claim]) -> set[str]:
    """Predictions with at least one unsure claim."""
    return {c.pred_uid for c in claims if c.unsure}


def reliability(pass1: list[Claim], pass2: list[Claim], universe: list[str]) -> dict:
    """Cohen's κ on (prediction, label) pairs, plus exact set agreement.

    Items unsure in either pass are excluded (D13) and reported. ``universe`` is the fixed
    label universe of the architecture (``CauseSet.labels()``).
    """
    sets1, sets2 = label_sets(pass1), label_sets(pass2)
    if set(sets1) != set(sets2):
        raise ValueError("the two passes annotate different predictions")
    excluded = unsure_items(pass1) | unsure_items(pass2)
    items = sorted(set(sets1) - excluded)
    a = b = c = d = 0
    per_label = {label: [0, 0, 0] for label in universe}
    for uid in items:
        for label in universe:
            x, y = label in sets1[uid], label in sets2[uid]
            a += x and y
            b += x and not y
            c += (not x) and y
            d += (not x) and (not y)
            if x and y:
                per_label[label][0] += 1
            elif x:
                per_label[label][1] += 1
            elif y:
                per_label[label][2] += 1
    unknown = {label for uid in items for label in sets1[uid] | sets2[uid]} - set(universe)
    if unknown:
        raise ValueError(f"labels outside the universe: {sorted(unknown)}")
    total = a + b + c + d
    result = {
        "items_total": len(sets1), "items_used": len(items),
        "items_excluded_unsure": len(excluded & set(sets1)),
        "excluded_share": _ratio(len(excluded & set(sets1)), len(sets1)),
        "pairs": total, "a": a, "b": b, "c": c, "d": d,
        "exact_set_agreement": _ratio(sum(sets1[u] == sets2[u] for u in items), len(items)),
        "positive_agreement": _ratio(2 * a, 2 * a + b + c),
        "per_label": {k: {"both": v[0], "pass1_only": v[1], "pass2_only": v[2]}
                      for k, v in per_label.items() if any(v)},
        "disagreements": [u for u in items if sets1[u] != sets2[u]],
        "kappa": None,
    }
    if total:
        p_o = (a + d) / total
        p1, p2 = (a + b) / total, (a + c) / total
        p_e = p1 * p2 + (1 - p1) * (1 - p2)
        result.update({"p_o": p_o, "p_e": p_e})
        if p_e < 1:
            result["kappa"] = (p_o - p_e) / (1 - p_e)
    return result


# --- Repeat sample ---------------------------------------------------------------------------


def _hash_key(seed: int, text: str) -> str:
    return hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()


def stratum(claims: list[Claim], causes: CauseSet) -> str:
    """Exclusive stratum of one prediction: pending/unsure, else sure cause, else no cause."""
    statuses = {status(c, causes) for c in claims}
    if P in statuses:
        return "pending_or_unsure"
    if M in statuses:
        return "sure_cause"
    return "no_cause"


def repeat_sample(
    first_pass: list[Claim],
    causes: CauseSet,
    excluded_uids: set[str],
    seed: int,
    first_pass_finished: str,
    size: int = 20,
    min_per_stratum: int = 4,
) -> dict:
    """Stratified, seeded sample for the repeat annotation (D12, P8).

    Eligible: annotated predictions without ``excluded_uids`` (the development cases). Each
    stratum gets at least ``min_per_stratum`` items where it has them; the rest is allocated
    in proportion (largest remainder). Inside a stratum the order is
    ``sha256("<seed>:<pred_uid>")``. The returned list is in a second, independent order.
    """
    by_prediction: dict[str, list[Claim]] = {}
    for claim in first_pass:
        by_prediction.setdefault(claim.pred_uid, []).append(claim)
    if any(not c.label for cs in by_prediction.values() for c in cs):
        raise ValueError("the first pass has unlabelled claims")
    pools: dict[str, list[str]] = {}
    for uid, cs in by_prediction.items():
        if uid not in excluded_uids:
            pools.setdefault(stratum(cs, causes), []).append(uid)
    for pool in pools.values():
        pool.sort(key=lambda uid: _hash_key(seed, uid))
    eligible = sum(len(p) for p in pools.values())
    target = min(size, eligible)
    take = {name: min(min_per_stratum, len(pool)) for name, pool in pools.items()}
    # Reduce the guarantee if the minimums alone exceed the target (small phases).
    while sum(take.values()) > target:
        largest = max(take, key=lambda n: take[n])
        take[largest] -= 1
    rest = target - sum(take.values())
    if rest:
        capacity = {n: len(pools[n]) - take[n] for n in pools}
        total_cap = sum(capacity.values())
        shares = {n: rest * capacity[n] / total_cap for n in pools} if total_cap else {}
        for n in shares:
            take[n] += min(capacity[n], math.floor(shares[n]))
        leftover = target - sum(take.values())
        for n in sorted(shares, key=lambda n: (-(shares[n] - math.floor(shares[n])), n)):
            if leftover <= 0:
                break
            if take[n] < len(pools[n]):
                take[n] += 1
                leftover -= 1
    selected = [uid for n in sorted(pools) for uid in pools[n][:take[n]]]
    order = sorted(selected, key=lambda uid: _hash_key(seed, f"repeat:{uid}"))
    not_before = datetime.fromisoformat(first_pass_finished) + timedelta(hours=24)
    return {
        "seed": seed, "size_requested": size, "eligible": eligible,
        "excluded_development_cases": len(excluded_uids & set(by_prediction)),
        "strata_eligible": {n: len(p) for n, p in sorted(pools.items())},
        "strata_selected": {n: take[n] for n in sorted(pools)},
        "first_pass_finished": first_pass_finished,
        "not_before": not_before.isoformat(),
        "selected": order,
    }
