import os
import time

from src.core import ThreatModeler
from src.deterministic.modeler import DeterministicThreatModeler
from src.evaluation.evaluator import evaluate, evaluate_by_difficulty
from src.models.loader import load_architecture, load_ground_truth
from src.models.threat import Difficulty
from src.RAG.llm import OllamaClient
from src.RAG.pipeline import RagThreatModeler

# Benchmark architectures ordered from simplest to most complex.
BENCHMARKS = [
    "simple_web_api",
    "webapp_with_auth",
    "microservices_async",
    "cloud_ingest_pipeline",
]

# Model used by LLM-backed approaches. Override with the OLLAMA_MODEL env var.
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")


def build_modelers() -> list[ThreatModeler]:
    """Assemble the approaches to compare.

    The deterministic baseline always runs. The RAG approach needs a running
    Ollama server, so it is opt-in via the RAG=1 env var to keep the default
    run dependency-free.
    """
    modelers: list[ThreatModeler] = [DeterministicThreatModeler()]

    if os.environ.get("RAG") == "1":
        modelers.append(RagThreatModeler(llm=OllamaClient(model=OLLAMA_MODEL)))

    return modelers


def run_benchmark(modeler: ThreatModeler, name: str) -> None:
    architecture = load_architecture(f"benchmark/{name}.json")
    ground_truth = load_ground_truth(f"benchmark/{name}.ground_truth.json")

    start = time.time()
    threats = modeler.analyze(architecture)
    elapsed = time.time() - start

    result = evaluate(threats, ground_truth)
    by_difficulty = evaluate_by_difficulty(threats, ground_truth)

    print(f"{architecture.name} ({name})")
    print(
        f"  Overall:  P={result.precision:.2f}  R={result.recall:.2f}  "
        f"F1={result.f1:.2f}  "
        f"(TP={result.true_positives} FP={result.false_positives} "
        f"FN={result.false_negatives})  [{elapsed:.1f}s]"
    )
    parts = []
    for difficulty in Difficulty:
        r = by_difficulty[difficulty]
        if r.total:
            parts.append(f"{difficulty.value}={r.detected}/{r.total} ({r.recall:.2f})")
    print(f"  Recall by difficulty:  {'  '.join(parts)}")
    print()


def main() -> None:
    for modeler in build_modelers():
        print(f"Approach: {modeler.name}")
        print("=" * 60)
        print()
        for name in BENCHMARKS:
            run_benchmark(modeler, name)


if __name__ == "__main__":
    main()
