"""One-off budget analysis of the free-loop agent's archived traces.

Diagnostic question (Phase 1 failure analysis): the free agent almost never
issues useful tool calls and under-reports. Is the 40-step budget the limiting
factor, and how is it spent? This breaks each free-agent trace down into:

- how the executed steps split across inspect / explore (get_connections) /
  retrieval (search_knowledge) / report_threat / overhead (list/finish),
- the control-flow interventions (loop / blocked_finish / unparseable),
- the final outcome (finished vs. max_steps),
- how many architecture elements were still NOT inspected at the end -- the
  direct signal of whether the budget capped coverage.

Reads archived traces (old schema) so it works on the data we already have.
Usage:  uv run python analyze_budget.py [glob]
"""

import glob
import json
import sys
from pathlib import Path

DEFAULT_GLOB = "results/traces_archive_*/*.json"
BENCHMARK_DIR = Path("benchmark")

# Group the agent's tools by purpose for the budget breakdown.
INSPECT = {"inspect_component", "inspect_data_flow"}
EXPLORE = {"get_connections"}
RETRIEVE = {"search_knowledge"}
OVERHEAD = {"list_components", "finish"}


def _element_count(architecture: str) -> int | None:
    """Total components + data flows for an architecture, or None if unknown."""
    path = BENCHMARK_DIR / f"{architecture}.json"
    if not path.exists():
        path = BENCHMARK_DIR / "holdout" / f"{architecture}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return len(data.get("components", [])) + len(data.get("data_flows", []))


def _inspected_ids(trace: dict) -> set[str]:
    """Element ids the agent actually inspected (last recorded coverage)."""
    inspected: set[str] = set()
    for s in trace.get("steps", []):
        for eid in s.get("inspected", []):
            inspected.add(eid)
    return inspected


def analyze(trace: dict) -> dict:
    steps = trace.get("steps", [])
    purpose = {"inspect": 0, "explore": 0, "retrieve": 0, "report": 0, "overhead": 0}
    for s in steps:
        if s.get("intervention"):
            continue  # not an executed tool step
        tool = s.get("tool")
        if tool in INSPECT:
            purpose["inspect"] += 1
        elif tool in EXPLORE:
            purpose["explore"] += 1
        elif tool in RETRIEVE:
            purpose["retrieve"] += 1
        elif tool == "report_threat":
            purpose["report"] += 1
        elif tool in OVERHEAD:
            purpose["overhead"] += 1

    total_elements = _element_count(trace["architecture"])
    inspected = len(_inspected_ids(trace))
    uninspected = (
        total_elements - inspected if total_elements is not None else None
    )

    return {
        "architecture": trace["architecture"],
        "outcome": trace.get("outcome"),
        "num_steps": trace.get("num_steps", len(steps)),
        "num_reported": trace.get("num_reported"),
        "purpose": purpose,
        "interventions": trace.get("intervention_counts", {}),
        "elements_total": total_elements,
        "elements_inspected": inspected,
        "elements_uninspected": uninspected,
    }


def main() -> None:
    pattern = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GLOB
    files = sorted(glob.glob(pattern))
    free = []
    for p in files:
        d = json.load(open(p))
        if "steps" in d:  # free-loop agent trace (old or new schema)
            free.append(d)

    if not free:
        print(f"No free-agent traces found in '{pattern}'.")
        return

    print(f"Free-loop agent budget analysis ({len(free)} trace(s))\n")
    header = (
        f"{'architecture':24} {'outcome':9} {'steps':>5} "
        f"{'insp':>4} {'expl':>4} {'retr':>4} {'rep':>4} {'ovh':>4}  "
        f"{'uninspected':>11}"
    )
    print(header)
    print("-" * len(header))
    for a in sorted((analyze(t) for t in free), key=lambda x: x["architecture"]):
        p = a["purpose"]
        uninsp = (
            f"{a['elements_uninspected']}/{a['elements_total']}"
            if a["elements_uninspected"] is not None else "?"
        )
        print(
            f"{a['architecture']:24} {str(a['outcome']):9} {a['num_steps']:>5} "
            f"{p['inspect']:>4} {p['explore']:>4} {p['retrieve']:>4} "
            f"{p['report']:>4} {p['overhead']:>4}  {uninsp:>11}"
        )

    # Aggregate signals that answer the diagnostic questions directly.
    n = len(free)
    hit_cap = sum(1 for t in free if t.get("outcome") == "max_steps")
    any_uninspected = 0
    total_explore = total_retrieve = 0
    for t in free:
        a = analyze(t)
        total_explore += a["purpose"]["explore"]
        total_retrieve += a["purpose"]["retrieve"]
        if a["elements_uninspected"]:
            any_uninspected += 1
    print()
    print(f"Hit step budget (max_steps): {hit_cap}/{n}")
    print(f"Runs ending with uninspected elements: {any_uninspected}/{n}")
    print(f"Total get_connections calls: {total_explore}")
    print(f"Total search_knowledge calls: {total_retrieve}")
    print(
        "\nReading: if 'uninspected' is 0 everywhere and outcome is 'finished', "
        "the 40-step budget did NOT cap coverage; under-reporting is then a "
        "reporting/decision problem, not a budget problem."
    )


if __name__ == "__main__":
    main()
