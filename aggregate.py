"""Aggregate benchmark runs recorded in results/results.jsonl.

Groups runs by (approach, model, architecture) and reports the mean and
standard deviation of precision, recall, F1, and latency across repeats, plus
mean per-difficulty recall. This turns the raw per-run log into the averaged,
variance-aware figures needed for a fair comparison.

Usage:
    uv run python aggregate.py [path/to/results.jsonl]
"""

import json
import statistics
import sys
from collections import defaultdict

from src.evaluation.results import DEFAULT_RESULTS_PATH
from src.models.threat import Difficulty


def load_runs(path: str) -> list[dict]:
    runs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                runs.append(json.loads(line))
    return runs


def _mean_std(values: list[float]) -> tuple[float, float]:
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, std


def aggregate(runs: list[dict]) -> None:
    # group key: approach + model + architecture
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for r in runs:
        key = (r["approach"], r["model"], r["architecture"])
        groups[key].append(r)

    # Sort by approach, then by the benchmark order they appear in.
    arch_order = {r["architecture"]: i for i, r in enumerate(runs)}
    for key in sorted(groups, key=lambda k: (k[0], k[1], arch_order[k[2]])):
        approach, model, architecture = key
        rows = groups[key]
        n = len(rows)

        p_m, p_s = _mean_std([r["precision"] for r in rows])
        r_m, r_s = _mean_std([r["recall"] for r in rows])
        f_m, f_s = _mean_std([r["f1"] for r in rows])
        l_m, l_s = _mean_std([r["latency_seconds"] for r in rows])

        model_label = "" if model == "none" else f" [{model}]"
        print(f"{approach}{model_label}  ·  {architecture}  (n={n})")
        print(f"  precision {p_m:.2f} ±{p_s:.2f}   recall {r_m:.2f} ±{r_s:.2f}   "
              f"f1 {f_m:.2f} ±{f_s:.2f}   latency {l_m:.1f}s ±{l_s:.1f}")

        # Mean per-difficulty recall across runs (only classes that appear).
        diff_recalls: dict[str, list[float]] = defaultdict(list)
        for r in rows:
            for d, vals in r.get("recall_by_difficulty", {}).items():
                diff_recalls[d].append(vals["recall"])
        parts = []
        for d in Difficulty:
            if d.value in diff_recalls:
                m, s = _mean_std(diff_recalls[d.value])
                parts.append(f"{d.value}={m:.2f} ±{s:.2f}")
        if parts:
            print(f"  recall by difficulty:  {'   '.join(parts)}")
        print()


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RESULTS_PATH
    try:
        runs = load_runs(path)
    except FileNotFoundError:
        print(f"No results file at '{path}'. Run the benchmark first.")
        return

    if not runs:
        print(f"No runs recorded in '{path}'.")
        return

    print(f"Aggregated {len(runs)} run(s) from {path}\n")
    aggregate(runs)


if __name__ == "__main__":
    main()
