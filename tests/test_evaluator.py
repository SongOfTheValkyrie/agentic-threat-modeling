"""Tests for the evaluator.

The evaluator matches predictions against ground truth on a (target, category)
key, so these tests pin down that matching logic and the precision/recall/F1
math, plus the per-difficulty recall breakdown.
"""

import pytest

from src.evaluation.evaluator import (
    evaluate,
    evaluate_by_difficulty,
    threat_key,
)
from src.models.threat import Difficulty, StrideCategory, Threat


def _threat(
    target: str,
    category: StrideCategory,
    *,
    is_flow: bool = False,
    difficulty: Difficulty | None = None,
) -> Threat:
    return Threat(
        id=f"{target}_{category.value}",
        component_id=None if is_flow else target,
        data_flow_id=target if is_flow else None,
        category=category,
        description="x",
        mitigation="y",
        difficulty=difficulty,
    )


def test_threat_key_uses_component_or_flow_and_category():
    comp = _threat("web", StrideCategory.SPOOFING)
    flow = _threat("flow_db", StrideCategory.TAMPERING, is_flow=True)

    assert threat_key(comp) == ("web", "spoofing")
    assert threat_key(flow) == ("flow_db", "tampering")


def test_threat_key_raises_without_target():
    orphan = Threat(
        id="x",
        category=StrideCategory.SPOOFING,
        description="x",
        mitigation="y",
    )
    with pytest.raises(ValueError):
        threat_key(orphan)


def test_perfect_match_scores_one():
    gt = [
        _threat("web", StrideCategory.SPOOFING),
        _threat("db", StrideCategory.INFORMATION_DISCLOSURE),
    ]
    result = evaluate(list(gt), gt)

    assert result.true_positives == 2
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0


def test_partial_match_counts_fp_and_fn():
    ground_truth = [
        _threat("web", StrideCategory.SPOOFING),
        _threat("db", StrideCategory.INFORMATION_DISCLOSURE),
    ]
    predictions = [
        _threat("web", StrideCategory.SPOOFING),  # TP
        _threat("web", StrideCategory.TAMPERING),  # FP
    ]
    result = evaluate(predictions, ground_truth)

    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_negatives == 1
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.f1 == pytest.approx(0.5)


def test_duplicate_predictions_are_deduplicated_by_key():
    # Same (target, category) twice must not inflate true positives, because
    # matching is set-based on the key.
    ground_truth = [_threat("web", StrideCategory.SPOOFING)]
    predictions = [
        _threat("web", StrideCategory.SPOOFING),
        _threat("web", StrideCategory.SPOOFING),
    ]
    result = evaluate(predictions, ground_truth)

    assert result.true_positives == 1
    assert result.false_positives == 0


def test_empty_predictions_score_zero_without_dividing_by_zero():
    ground_truth = [_threat("web", StrideCategory.SPOOFING)]
    result = evaluate([], ground_truth)

    assert result.true_positives == 0
    assert result.false_negatives == 1
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_evaluate_by_difficulty_reports_recall_per_class():
    ground_truth = [
        _threat("web", StrideCategory.SPOOFING, difficulty=Difficulty.EASY),
        _threat(
            "flow",
            StrideCategory.INFORMATION_DISCLOSURE,
            is_flow=True,
            difficulty=Difficulty.HARD,
        ),
        _threat(
            "db",
            StrideCategory.ELEVATION_OF_PRIVILEGE,
            difficulty=Difficulty.HARD,
        ),
    ]
    # Detect the easy one and one of the two hard ones.
    predictions = [
        _threat("web", StrideCategory.SPOOFING),
        _threat("db", StrideCategory.ELEVATION_OF_PRIVILEGE),
    ]
    by_diff = evaluate_by_difficulty(predictions, ground_truth)

    assert by_diff[Difficulty.EASY].detected == 1
    assert by_diff[Difficulty.EASY].total == 1
    assert by_diff[Difficulty.EASY].recall == 1.0

    assert by_diff[Difficulty.HARD].detected == 1
    assert by_diff[Difficulty.HARD].total == 2
    assert by_diff[Difficulty.HARD].recall == 0.5

    # No medium-difficulty ground truth: recall defaults to 0.0, total 0.
    assert by_diff[Difficulty.MEDIUM].total == 0
    assert by_diff[Difficulty.MEDIUM].recall == 0.0


def test_evaluate_by_difficulty_ignores_untagged_ground_truth():
    ground_truth = [
        _threat("web", StrideCategory.SPOOFING, difficulty=Difficulty.EASY),
        _threat("db", StrideCategory.TAMPERING, difficulty=None),
    ]
    by_diff = evaluate_by_difficulty([], ground_truth)

    # The untagged threat belongs to no difficulty class, so every class total
    # reflects only the tagged threats.
    assert by_diff[Difficulty.EASY].total == 1
    assert by_diff[Difficulty.MEDIUM].total == 0
    assert by_diff[Difficulty.HARD].total == 0
