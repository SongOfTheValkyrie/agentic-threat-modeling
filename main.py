import os
import time

from src.agent.modeler import AgentThreatModeler
from src.agent.structured import StructuredAgentThreatModeler
from src.agent.trace import write_trace
from src.core import ThreatModeler
from src.deterministic.modeler import DeterministicThreatModeler
from src.evaluation.evaluator import evaluate, evaluate_by_difficulty
from src.evaluation.results import RunRecord, append_result
from src.models.loader import load_architecture, load_ground_truth
from src.models.threat import Difficulty
from src.RAG.llm import OllamaClient
from src.RAG.pipeline import RagThreatModeler

# Development benchmark: used while building and diagnosing the approaches.
DEV_BENCHMARKS = [
    "simple_web_api",
    "webapp_with_auth",
    "microservices_async",
    "cloud_ingest_pipeline",
    "multi_tenant_saas",
]

# Holdout test set: previously unused architectures for the final evaluation,
# kept in benchmark/holdout/ to make the dev/holdout split explicit.
HOLDOUT_BENCHMARKS = [
    "holdout/cicd_pipeline",
    "holdout/mobile_banking",
]

# Select the set with HOLDOUT=1 (otherwise the development benchmark runs).
_selected = (
    HOLDOUT_BENCHMARKS if os.environ.get("HOLDOUT") == "1" else DEV_BENCHMARKS
)

# ONLY=<name>[,<name>...] narrows the run to specific architectures, matched by
# their bare id (ignoring any "holdout/" prefix). Useful for a quick, targeted
# trace of one approach on one architecture instead of the full sweep.
_only = os.environ.get("ONLY", "").strip()
if _only:
    wanted = {name.strip().rsplit("/", 1)[-1] for name in _only.split(",")}
    BENCHMARKS = [b for b in _selected if b.rsplit("/", 1)[-1] in wanted]
    if not BENCHMARKS:
        available = [b.rsplit("/", 1)[-1] for b in _selected]
        raise SystemExit(
            f"ONLY={_only!r} matched no architecture in the selected set. "
            f"Available: {available}"
        )
else:
    BENCHMARKS = _selected

# Model used by LLM-backed approaches. Override with the OLLAMA_MODEL env var.
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")

# Number of repetitions per configuration. LLM runs vary between repeats, so
# several runs are needed before averaging produces reliable figures.
RUNS = int(os.environ.get("RUNS", "1"))

# With TRACE=1, write a per-run execution trace for any agent that exposes one
# (both agent variants do). Off by default: traces are large and only needed
# when diagnosing agent behaviour, not for the headline metrics.
TRACE = os.environ.get("TRACE") == "1"


def build_modelers() -> list[ThreatModeler]:
    """Assemble the approaches to compare.

    The deterministic baseline always runs. The RAG and agent approaches need a
    running Ollama server, so they are opt-in via the RAG=1 and AGENT=1 env vars
    to keep the default run dependency-free.
    """
    modelers: list[ThreatModeler] = [DeterministicThreatModeler()]

    if os.environ.get("RAG") == "1":
        modelers.append(RagThreatModeler(llm=OllamaClient(model=OLLAMA_MODEL)))

    if os.environ.get("AGENT") == "1":
        modelers.append(AgentThreatModeler(llm=OllamaClient(model=OLLAMA_MODEL)))

    if os.environ.get("AGENT_PEV") == "1":
        modelers.append(
            StructuredAgentThreatModeler(llm=OllamaClient(model=OLLAMA_MODEL))
        )

    # Ablation variants of agent_pev (baseline above stays unchanged). Each
    # disables one phase to isolate its contribution; they carry distinct
    # approach labels so their results can be told apart.
    if os.environ.get("AGENT_PEV_NOPLAN") == "1":
        modelers.append(
            StructuredAgentThreatModeler(
                llm=OllamaClient(model=OLLAMA_MODEL), use_plan=False
            )
        )

    if os.environ.get("AGENT_PEV_NOVERIFY") == "1":
        modelers.append(
            StructuredAgentThreatModeler(
                llm=OllamaClient(model=OLLAMA_MODEL), use_verify=False
            )
        )

    # Ablation: PEV without adaptive deepening (plan/retrieval/verify intact).
    # Isolates the contribution of the adaptive exploration itself.
    if os.environ.get("AGENT_PEV_NODEEPEN") == "1":
        modelers.append(
            StructuredAgentThreatModeler(
                llm=OllamaClient(model=OLLAMA_MODEL), use_deepening=False
            )
        )

    # Experiment variant: context-rich deepening prompt (not an ablation; it
    # adds information rather than removing a phase).
    if os.environ.get("AGENT_PEV_RICHDEEPEN") == "1":
        modelers.append(
            StructuredAgentThreatModeler(
                llm=OllamaClient(model=OLLAMA_MODEL), rich_deepen=True
            )
        )

    # Experiment variant: adaptive deepening prompt (stopping is valid, tools
    # separated by purpose, repeat queries discouraged). The targeted iteration
    # to make deepening actually adaptive.
    if os.environ.get("AGENT_PEV_ADAPTIVEDEEPEN") == "1":
        modelers.append(
            StructuredAgentThreatModeler(
                llm=OllamaClient(model=OLLAMA_MODEL), adaptive_deepen=True
            )
        )

    return modelers


def _usage(modeler: ThreatModeler) -> dict:
    """Read per-run usage counters from an LLM-backed modeler, if available."""
    client = getattr(modeler, "_llm", None)
    usage: dict = {}
    if client is not None and hasattr(client, "llm_calls"):
        usage["llm_calls"] = client.llm_calls
        usage["tokens"] = getattr(client, "tokens", None)
    tool_box = getattr(modeler, "last_tool_box", None)
    if tool_box is not None and hasattr(tool_box, "retrieval_calls"):
        usage["retrieval_calls"] = tool_box.retrieval_calls
    return usage


def run_benchmark(modeler: ThreatModeler, name: str, run_index: int = 0) -> None:
    architecture = load_architecture(f"benchmark/{name}.json")
    ground_truth = load_ground_truth(f"benchmark/{name}.ground_truth.json")
    # Log the bare architecture id without any "holdout/" path prefix.
    arch_label = name.rsplit("/", 1)[-1]

    # Snapshot usage counters so we can report per-run deltas.
    client = getattr(modeler, "_llm", None)
    calls_before = getattr(client, "llm_calls", 0) if client else 0
    tokens_before = getattr(client, "tokens", 0) if client else 0

    start = time.time()
    threats = modeler.analyze(architecture)
    elapsed = time.time() - start

    # Optionally persist the agent's execution trace for offline diagnosis.
    # Only agents expose ``last_trace``; other approaches are skipped silently.
    trace_path = None
    if TRACE:
        trace = getattr(modeler, "last_trace", None)
        if trace is not None:
            trace_path = write_trace(trace)

    result = evaluate(threats, ground_truth)
    by_difficulty = evaluate_by_difficulty(threats, ground_truth)

    usage = _usage(modeler)
    llm_calls = usage.get("llm_calls")
    if llm_calls is not None:
        llm_calls -= calls_before
    tokens = usage.get("tokens")
    if tokens is not None and tokens_before:
        tokens -= tokens_before

    # Model name comes from the modeler's LLM client when it has one; the
    # deterministic baseline has none.
    model = getattr(client, "model", None) or "none"
    append_result(
        RunRecord(
            approach=modeler.name,
            model=model,
            architecture=arch_label,
            result=result,
            by_difficulty=by_difficulty,
            latency_seconds=elapsed,
            num_threats=len(threats),
            run_index=run_index,
            llm_calls=llm_calls,
            retrieval_calls=usage.get("retrieval_calls"),
            tokens=tokens,
        )
    )

    print(f"{architecture.name} ({arch_label})")
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
    if trace_path is not None:
        print(f"  Trace: {trace_path}")
    print()


def main() -> None:
    modelers = build_modelers()

    # Build modelers once, then repeat the full sweep RUNS times. Each repeat
    # gets a distinct run_index so the appended results can be told apart and
    # averaged later.
    for run_index in range(RUNS):
        if RUNS > 1:
            print(f"\n########## RUN {run_index + 1} / {RUNS} ##########\n")
        for modeler in modelers:
            print(f"Approach: {modeler.name}")
            print("=" * 60)
            print()
            for name in BENCHMARKS:
                run_benchmark(modeler, name, run_index=run_index)


if __name__ == "__main__":
    main()
