from src.deterministic.rules import detect_threats
from src.evaluation.evaluator import evaluate, evaluate_by_difficulty
from src.models.loader import load_architecture, load_ground_truth
from src.models.threat import Difficulty

# Benchmark architectures ordered from simplest to most complex.
BENCHMARKS = [
    "simple_web_api",
    "webapp_with_auth",
    "microservices_async",
    "cloud_ingest_pipeline",
]


def run_benchmark(name: str) -> None:
    architecture = load_architecture(f"benchmark/{name}.json")
    ground_truth = load_ground_truth(f"benchmark/{name}.ground_truth.json")

    threats = detect_threats(architecture)
    result = evaluate(threats, ground_truth)
    by_difficulty = evaluate_by_difficulty(threats, ground_truth)

    print(f"{architecture.name} ({name})")
    print(
        f"  Overall:  P={result.precision:.2f}  R={result.recall:.2f}  "
        f"F1={result.f1:.2f}  "
        f"(TP={result.true_positives} FP={result.false_positives} "
        f"FN={result.false_negatives})"
    )
    parts = []
    for difficulty in Difficulty:
        r = by_difficulty[difficulty]
        if r.total:
            parts.append(f"{difficulty.value}={r.detected}/{r.total} ({r.recall:.2f})")
    print(f"  Recall by difficulty:  {'  '.join(parts)}")
    print()


def main() -> None:
    print("Deterministic baseline across benchmark architectures")
    print("=" * 60)
    print()
    for name in BENCHMARKS:
        run_benchmark(name)


if __name__ == "__main__":
    main()
