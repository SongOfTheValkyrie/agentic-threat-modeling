"""Summarize agent execution traces for offline diagnosis.

Reads the per-run trace JSON files written to results/traces/ (see
src/agent/trace.py) and prints a compact per-architecture summary for each
agent type, so behavioural patterns can be read at a glance instead of opening
every file.

For the free-loop agent it reports the outcome and control-flow interventions
(premature finishes blocked, loops redirected, unparseable outputs).

For the Plan-Explore-Verify agent it reports plan coverage, whether adaptive
deepening was actually used or was a no-op, and the proposed/confirmed/dropped
candidate counts that show where threats are lost.

Usage:
    uv run python trace_summary.py [results/traces]
"""

import glob
import json
import os
import sys

DEFAULT_TRACE_DIR = "results/traces"


def _load(directory: str) -> list[dict]:
    traces = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path) as f:
            traces.append(json.load(f))
    return traces


def _is_pev(trace: dict) -> bool:
    return trace.get("agent") == "agent_pev"


def _summarize_free(trace: dict) -> str:
    interventions = trace.get("intervention_counts", {})
    tools = trace.get("tool_counts", {})
    parts = [
        f"outcome={trace.get('outcome', '?')}",
        f"steps={trace.get('num_steps', 0)}",
        f"reported={trace.get('num_reported', 0)}",
        f"search_knowledge={tools.get('search_knowledge', 0)}",
    ]
    if interventions:
        inter = " ".join(f"{k}={v}" for k, v in sorted(interventions.items()))
        parts.append(f"interventions[{inter}]")
    else:
        parts.append("interventions[none]")
    return "  ".join(parts)


def _deepen_stats(trace: dict) -> tuple[int, int]:
    """Return (prioritized_elements, elements_with_a_successful_deepening_call).

    A deepening call counts only when a tool actually ran and returned
    (``tool_success``); an aborted turn (done / invalid_json / unknown_tool)
    does not.
    """
    prioritized = 0
    really_deepened = 0
    for e in trace.get("elements", []):
        if e.get("prioritized"):
            prioritized += 1
        if any(s.get("tool_success") for s in e.get("deepen_steps", [])):
            really_deepened += 1
    return prioritized, really_deepened


def _termination_reasons(trace: dict) -> dict[str, int]:
    """Count why deepening turns ended across all elements of one trace.

    This separates a deliberate stop ("done") from a formatting/capability
    failure ("invalid_json", "unknown_tool", "tool_error"), which the earlier
    trace could not distinguish.
    """
    counts: dict[str, int] = {}
    for e in trace.get("elements", []):
        for s in e.get("deepen_steps", []):
            reason = s.get("termination_reason")
            if reason:
                counts[reason] = counts.get(reason, 0) + 1
    return counts


def _summarize_pev(trace: dict) -> str:
    totals = trace.get("totals", {})
    prioritized, really_deepened = _deepen_stats(trace)
    reasons = _termination_reasons(trace)
    reason_str = (
        " ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
        if reasons else "none"
    )
    return "  ".join([
        f"reported={trace.get('num_reported', 0)}",
        f"elements={trace.get('num_elements', 0)}",
        f"prioritized={prioritized}",
        f"deepened_real={really_deepened}/{prioritized}",
        f"proposed={totals.get('proposed', 0)}",
        f"confirmed={totals.get('confirmed', 0)}",
        f"dropped={totals.get('dropped', 0)}",
        f"deepen_end[{reason_str}]",
    ])


def main() -> None:
    directory = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TRACE_DIR
    traces = _load(directory)
    if not traces:
        print(f"No traces found in '{directory}'. Run with TRACE=1 first.")
        return

    free = [t for t in traces if not _is_pev(t)]
    pev = [t for t in traces if _is_pev(t)]

    if free:
        print("=== Free-loop agent (agent) ===")
        for t in sorted(free, key=lambda x: x["architecture"]):
            print(f"{t['architecture']:24} {_summarize_free(t)}")
        print()

    if pev:
        print("=== Plan-Explore-Verify agent (agent_pev) ===")
        for t in sorted(pev, key=lambda x: x["architecture"]):
            print(f"{t['architecture']:24} {_summarize_pev(t)}")

        # Aggregate the key finding: how often adaptive deepening succeeded,
        # and when it did not, whether the model chose to stop ("done") or
        # failed to produce a usable action (invalid_json / unknown_tool).
        total_prio = total_real = 0
        agg_reasons: dict[str, int] = {}
        for t in pev:
            p, r = _deepen_stats(t)
            total_prio += p
            total_real += r
            for k, v in _termination_reasons(t).items():
                agg_reasons[k] = agg_reasons.get(k, 0) + v
        print()
        print(
            f"Adaptive deepening: {total_real}/{total_prio} prioritized elements "
            f"had a successful extra tool call."
        )
        if agg_reasons:
            reason_str = "  ".join(
                f"{k}={v}" for k, v in sorted(agg_reasons.items())
            )
            print(f"Deepening turns ended by:  {reason_str}")
            print(
                "  (\"done\" = model chose to stop; \"invalid_json\" / "
                "\"unknown_tool\" = it could not form a valid action.)"
            )


if __name__ == "__main__":
    main()
