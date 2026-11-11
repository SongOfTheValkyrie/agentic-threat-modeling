#!/usr/bin/env python3
"""Per-run report for the model diagnostic (EXPERIMENTS.md, "Diagnostic: is
situation-dependent tool choice limited by the model?").

Reads what one sandboxed run wrote (``results.jsonl`` and the PEV traces) and
reports, per approach: the tool calls, the deepening steps, the termination
decision for each prioritized element, LLM calls, tokens and runtime, as far as
the existing instrumentation records them. Missing values stay ``null``.

The report states observations only. How to read them (supports / speaks
against / inconclusive) was fixed in EXPERIMENTS.md before any Qwen output
existed, and is left to the reader. This file draws no conclusion, and detection
quality (F1, keys) is listed for completeness, not for ranking models.

Usage (normally called by scripts/run_qwen_diagnostic.sh)::

    python scripts/diagnostic_report.py --results-dir DIR --out-dir DIR \\
        --model qwen2.5:7b --architecture multi_tenant_saas \\
        --approaches agent_pev,agent_pev_adaptivedeepen [--ollama-tags FILE]

Exit code 0: report written, no problems. 1: report written, problems listed in it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

FAILURE_REASONS = ("invalid_json", "unknown_tool", "tool_error")
# An argument value that is a template placeholder copied from the prompt, e.g. "<id>".
PLACEHOLDER = re.compile(r"<[^<>]+>")
HEAD = 200  # characters of a failed step's raw reply kept in the report
REPO = Path(__file__).resolve().parents[1]


# --- reading ---------------------------------------------------------------------


def load_rows(results_dir: Path) -> list[dict]:
    path = results_dir / "results.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_traces(results_dir: Path) -> tuple[list[dict], list[str]]:
    traces: list[dict] = []
    problems: list[str] = []
    directory = results_dir / "traces"
    if not directory.exists():
        return traces, problems
    for path in sorted(directory.glob("*.json")):
        try:
            traces.append(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            problems.append(f"trace {path.name} is not valid JSON: {exc}")
    return traces, problems


# --- per element -----------------------------------------------------------------


def summarize_element(element: dict) -> dict:
    """One prioritized element: its deepening steps and how deepening ended."""
    steps = element.get("deepen_steps") or []
    out_steps = []
    queries: list[str] = []
    by_tool: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    attempted: list[str] = []
    placeholder_steps = 0
    for step in steps:
        args = step.get("args") or {}
        success = bool(step.get("tool_success"))
        reason = step.get("termination_reason")
        item = {
            "tool": step.get("tool"),
            "args": args,
            "tool_success": success,
            "termination_reason": reason,
        }
        if not success and step.get("raw_response"):
            item["raw_response_head"] = str(step["raw_response"])[:HEAD]
        out_steps.append(item)
        if success:
            by_tool[str(step.get("tool"))] += 1
            if step.get("tool") == "search_knowledge":
                queries.append(str(args.get("query", "")).strip())
        if reason in FAILURE_REASONS:
            failures[reason] += 1
        # Post hoc: the choice made at this step, apart from whether the call worked.
        token = step.get("tool") or (reason if reason in FAILURE_REASONS else None)
        if token:
            attempted.append(str(token))
        if any(isinstance(v, str) and PLACEHOLDER.fullmatch(v.strip()) for v in args.values()):
            placeholder_steps += 1
    final = next(
        (s["termination_reason"] for s in reversed(steps) if s.get("termination_reason")),
        None,
    )
    return {
        "element_id": element.get("element_id"),
        "kind": element.get("kind"),
        "hypothesis": element.get("hypothesis") or None,
        "steps": out_steps,
        "tool_calls": sum(by_tool.values()),
        "tool_calls_by_tool": dict(by_tool),
        "final_termination": final,
        "repeated_identical_queries": len(queries) - len(set(queries)),
        "failure_reasons": dict(failures),
        "attempted_tools": attempted,
        "placeholder_argument_steps": placeholder_steps,
    }


def indicators(per_element: list[dict]) -> dict:
    """Mechanical facts named after the observations pre-registered in
    EXPERIMENTS.md. No verdict is derived from them."""
    with_data = [e for e in per_element if e["steps"]]
    by_tool: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    for e in per_element:
        by_tool.update(e["tool_calls_by_tool"])
        failures.update(e["failure_reasons"])
    terminations = Counter(e["final_termination"] or "none_recorded" for e in per_element)
    sequences = [e["attempted_tools"] for e in with_data if e["attempted_tools"]]
    common = min((len(s) for s in sequences), default=0)
    behaviours = {
        (e["final_termination"], tuple(sorted(e["tool_calls_by_tool"])))
        for e in with_data
    }
    return {
        "prioritized_elements": len(per_element),
        "elements_with_deepening_steps": len(with_data),
        "deepening_data_available": bool(with_data),
        "final_termination_counts": dict(terminations),
        "same_termination_for_all_prioritized": (
            len({e["final_termination"] for e in with_data}) == 1 if with_data else None
        ),
        "element_dependent_behaviour": len(behaviours) > 1 if with_data else None,
        "tool_calls_by_tool": dict(by_tool),
        "get_connections_calls": by_tool.get("get_connections", 0),
        "search_knowledge_only": (set(by_tool) == {"search_knowledge"}) if by_tool else None,
        "elements_with_repeated_identical_query": sum(
            1 for e in per_element if e["repeated_identical_queries"]
        ),
        "elements_with_done": sum(1 for e in per_element if e["final_termination"] == "done"),
        "elements_with_tool_calls": sum(1 for e in per_element if e["tool_calls"]),
        "invalid_json_steps": failures.get("invalid_json", 0),
        "unknown_tool_steps": failures.get("unknown_tool", 0),
        "tool_error_steps": failures.get("tool_error", 0),
        # Added after the first Qwen run (post hoc, not in the pre-registration):
        "attempted_tool_sequences": dict(Counter(" > ".join(s) for s in sequences)),
        "tool_choice_same_over_common_prefix": (
            len({tuple(s[:common]) for s in sequences}) == 1 if common else None
        ),
        "placeholder_argument_steps": sum(e["placeholder_argument_steps"] for e in per_element),
    }


# --- per approach ----------------------------------------------------------------


def approach_report(approach: str, row: dict | None, trace: dict | None) -> dict:
    elements = (trace or {}).get("elements") or []
    prioritized = [e for e in elements if e.get("prioritized")]
    per_element = [summarize_element(e) for e in prioritized]
    run = None
    quality = None
    if row is not None:
        run = {
            "model": row.get("model"),
            "latency_seconds": row.get("latency_seconds"),
            "llm_calls": row.get("llm_calls"),
            "tokens": row.get("tokens"),
            "retrieval_calls": row.get("retrieval_calls"),
            "num_threats": row.get("num_threats"),
        }
        quality = {
            "note": "reported for completeness; not used to rank models",
            "f1": row.get("f1"),
            "precision": row.get("precision"),
            "recall": row.get("recall"),
            "true_positives": row.get("true_positives"),
            "false_positives": row.get("false_positives"),
            "false_negatives": row.get("false_negatives"),
            "matched_keys": row.get("matched_keys"),
            "missed_keys": row.get("missed_keys"),
        }
    return {
        "approach": approach,
        "run": run,
        "plan": {
            "priorities": (trace or {}).get("priorities"),
            "elements_total": (trace or {}).get("num_elements"),
        },
        "deepening": {
            "per_element": per_element,
            "observations": indicators(per_element),
        },
        "quality": quality,
    }


# --- whole report ----------------------------------------------------------------


def ollama_model_info(tags_file: Path | None, model: str) -> dict | None:
    if tags_file is None or not tags_file.exists():
        return None
    models = json.loads(tags_file.read_text()).get("models", [])
    names = {model, f"{model}:latest"} if ":" not in model else {model}
    for entry in models:
        if entry.get("name") in names:
            return {
                key: entry.get(key) for key in ("name", "digest", "size", "modified_at")
            }
    return None


def code_version() -> dict:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            check=True, timeout=10, cwd=REPO,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True, timeout=10, cwd=REPO,
        ).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "tracked_files_differ_from_commit": None}
    return {"commit": commit, "tracked_files_differ_from_commit": dirty}


def build_report(
    results_dir: Path,
    *,
    model: str,
    architecture: str,
    approaches: list[str],
    tags_file: Path | None = None,
) -> dict:
    rows = [r for r in load_rows(results_dir) if r.get("architecture") == architecture]
    traces, problems = load_traces(results_dir)
    reports = []
    for approach in approaches:
        matching_rows = [r for r in rows if r.get("approach") == approach]
        matching_traces = [
            t for t in traces
            if t.get("agent") == approach and t.get("architecture") == architecture
        ]
        row = matching_rows[0] if len(matching_rows) == 1 else None
        trace = matching_traces[0] if len(matching_traces) == 1 else None
        if len(matching_rows) != 1:
            problems.append(f"{approach}: expected 1 result row, found {len(matching_rows)}")
        if len(matching_traces) != 1:
            problems.append(f"{approach}: expected 1 trace, found {len(matching_traces)}")
        if row is not None and row.get("model") != model:
            problems.append(
                f"{approach}: result row names model {row.get('model')!r}, requested {model!r}"
            )
        reports.append(approach_report(approach, row, trace))
    return {
        "schema": "model-diagnostic-report",
        "version": 1,
        "meta": {
            "generated_at": datetime.now(UTC).isoformat(),
            "requested_model": model,
            "ollama_model": ollama_model_info(tags_file, model),
            "architecture": architecture,
            "approaches": approaches,
            "runs_per_approach": 1,
            "post_hoc": {
                "fields": [
                    "attempted_tool_sequences",
                    "tool_choice_same_over_common_prefix",
                    "placeholder_argument_steps",
                ],
                "note": (
                    "Added after the first Qwen run to separate the tool chosen at a step "
                    "from whether the call worked. Not part of the pre-registration."
                ),
            },
            "reading": (
                "One run is a diagnostic hint, not a rate. Reading rules are in "
                "EXPERIMENTS.md and were fixed before this run."
            ),
            "code": code_version(),
        },
        "problems": problems,
        "approaches": reports,
    }


# --- rendering -------------------------------------------------------------------


def _fmt(value) -> str:
    return "n/a" if value is None else str(value)


def render_markdown(report: dict) -> str:
    meta = report["meta"]
    lines = [
        f"# Model diagnostic: {meta['requested_model']} on {meta['architecture']}",
        "",
        "Observations only; no conclusion is drawn here. One run per approach is a "
        "diagnostic hint. Reading rules: EXPERIMENTS.md, section \"Diagnostic: is "
        "situation-dependent tool choice limited by the model?\".",
        "",
    ]
    info = meta.get("ollama_model")
    if info:
        lines.append(f"Model digest: `{_fmt(info.get('digest'))}`, size {_fmt(info.get('size'))}.")
    code = meta.get("code") or {}
    differs = _fmt(code.get("tracked_files_differ_from_commit"))
    lines += [
        f"Code commit: `{_fmt(code.get('commit'))}` (tracked files differ from commit: {differs}).",
        "",
    ]
    if report["problems"]:
        lines.append("## Problems")
        lines += [f"- {p}" for p in report["problems"]]
        lines.append("")
    lines += [
        "## Run cost",
        "",
        "| approach | LLM calls | tokens | retrieval calls | runtime (s) | threats |",
        "|---|---|---|---|---|---|",
    ]
    for a in report["approaches"]:
        r = a["run"] or {}
        lines.append(
            f"| {a['approach']} | {_fmt(r.get('llm_calls'))} | {_fmt(r.get('tokens'))} | "
            f"{_fmt(r.get('retrieval_calls'))} | {_fmt(r.get('latency_seconds'))} | "
            f"{_fmt(r.get('num_threats'))} |"
        )
    lines.append("")
    for a in report["approaches"]:
        obs = a["deepening"]["observations"]
        lines += [f"## {a['approach']}", ""]
        total = _fmt(a["plan"]["elements_total"])
        lines.append(
            f"Plan priorities: {_fmt(a['plan']['priorities'])} "
            f"({obs['prioritized_elements']} prioritized of {total} elements)."
        )
        if not obs["deepening_data_available"]:
            lines += ["", "No deepening steps were recorded; nothing to read for tool choice.", ""]
        else:
            lines += [
                "",
                "| element | final decision | tool calls | by tool | repeated identical queries |",
                "|---|---|---|---|---|",
            ]
            for e in a["deepening"]["per_element"]:
                lines.append(
                    f"| {e['element_id']} | {_fmt(e['final_termination'])} | {e['tool_calls']} | "
                    f"{e['tool_calls_by_tool'] or '-'} | {e['repeated_identical_queries']} |"
                )
            lines += ["", "Deepening steps per element:", ""]
            for e in a["deepening"]["per_element"]:
                lines.append(f"- **{e['element_id']}**")
                for s in e["steps"]:
                    detail = s["args"].get("query") or s["args"].get("component_id") or ""
                    status = "ok" if s["tool_success"] else _fmt(s["termination_reason"])
                    head = f" raw: `{s['raw_response_head']}`" if s.get("raw_response_head") else ""
                    lines.append(f"  - {_fmt(s['tool'])} {detail!r} -> {status}{head}")
            lines += ["", "Observations named in the pre-registration:", ""]
            for key in (
                "same_termination_for_all_prioritized", "element_dependent_behaviour",
                "final_termination_counts", "tool_calls_by_tool", "get_connections_calls",
                "search_knowledge_only", "elements_with_repeated_identical_query",
                "elements_with_done", "invalid_json_steps", "unknown_tool_steps",
                "tool_error_steps",
            ):
                lines.append(f"- {key}: {_fmt(obs[key])}")
            lines += [
                "",
                "Added after the first Qwen run (post hoc, not in the pre-registration):",
                "",
            ]
            for key in (
                "attempted_tool_sequences", "tool_choice_same_over_common_prefix",
                "placeholder_argument_steps",
            ):
                lines.append(f"- {key}: {_fmt(obs[key])}")
            lines.append("")
        q = a["quality"]
        if q:
            lines += [
                f"Detection (not for ranking models): F1 {_fmt(q['f1'])}, "
                f"TP/FP/FN {_fmt(q['true_positives'])}/{_fmt(q['false_positives'])}/"
                f"{_fmt(q['false_negatives'])}.",
                "",
            ]
    return "\n".join(lines)


# --- command line ----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--approaches", required=True, help="comma separated")
    parser.add_argument("--ollama-tags", type=Path, default=None)
    args = parser.parse_args(argv)

    report = build_report(
        args.results_dir,
        model=args.model,
        architecture=args.architecture,
        approaches=[a.strip() for a in args.approaches.split(",") if a.strip()],
        tags_file=args.ollama_tags,
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "diagnostic_report.json"
    md_path = args.out_dir / "diagnostic_report.md"
    for path in (json_path, md_path):
        if path.exists():
            print(f"Refusing to overwrite {path}", file=sys.stderr)
            return 4
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    md_path.write_text(render_markdown(report) + "\n")
    print(f"Wrote {json_path} and {md_path}")
    for problem in report["problems"]:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
