from dataclasses import dataclass

from src.models.threat import Difficulty, Threat


@dataclass
class EvaluationResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


@dataclass
class DifficultyRecall:
    """Recall for a single difficulty class.

    ``detected`` / ``total`` is how many ground-truth threats of this class the
    predictions covered. Precision is intentionally not reported per class,
    because a prediction's difficulty is a property of the ground truth, not of
    the prediction, so false positives cannot be attributed to a class.
    """

    detected: int
    total: int
    recall: float


def threat_key(threat: Threat) -> tuple[str, str]:
    target = threat.component_id or threat.data_flow_id

    if target is None:
        raise ValueError("Threat must reference a component or data flow.")

    return target, threat.category.value


def evaluate(
    predictions: list[Threat],
    ground_truth: list[Threat],
) -> EvaluationResult:

    predicted_keys = {threat_key(t) for t in predictions}
    ground_truth_keys = {threat_key(t) for t in ground_truth}

    true_positives = len(predicted_keys & ground_truth_keys)
    false_positives = len(predicted_keys - ground_truth_keys)
    false_negatives = len(ground_truth_keys - predicted_keys)

    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 0.0
    )

    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return EvaluationResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def evaluate_by_difficulty(
    predictions: list[Threat],
    ground_truth: list[Threat],
) -> dict[Difficulty, DifficultyRecall]:
    """Recall broken down by the difficulty class of each ground-truth threat.

    This is the central metric for the experiment: it shows how coverage
    degrades as threats require more security knowledge to find. Ground-truth
    threats without a difficulty tag are ignored here.
    """

    predicted_keys = {threat_key(t) for t in predictions}

    results: dict[Difficulty, DifficultyRecall] = {}
    for difficulty in Difficulty:
        class_keys = {
            threat_key(t) for t in ground_truth if t.difficulty == difficulty
        }
        total = len(class_keys)
        detected = len(class_keys & predicted_keys)
        recall = detected / total if total else 0.0
        results[difficulty] = DifficultyRecall(
            detected=detected,
            total=total,
            recall=recall,
        )

    return results