#!/usr/bin/env python3
"""Render the draft cause lists into a single review sheet (Markdown).

The sheet is generated, never hand-edited: the JSON files under
``benchmark_v2/draft/`` are the source of truth, and a test keeps the committed
sheet in sync with them.

Usage (from the repository root)::

    python scripts/render_cause_review.py            # write benchmark_v2/draft/REVIEW.md
    python scripts/render_cause_review.py --check    # exit 1 if the sheet is stale
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_DIR = ROOT / "benchmark_v2" / "draft"
OUTPUT = DRAFT_DIR / "REVIEW.md"
# Fixed order so the sheet is stable regardless of directory listing order.
ORDER = ["multi_tenant_saas", "cloud_ingest_pipeline"]


def cell(text: object) -> str:
    """Make a value safe for a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def code(value: object) -> str:
    return f"`{json.dumps(value) if not isinstance(value, str) else value}`"


def evidence_lines(evidence: list[dict]) -> list[str]:
    return [
        f"{code(e['path'])} = {code(e['observed'])}"
        + (f" *({e['role']})*" if "role" in e else "")
        for e in evidence
    ]


def load_drafts() -> list[dict]:
    drafts = {}
    for path in sorted(DRAFT_DIR.glob("*.causes.json")):
        draft = json.loads(path.read_text())
        drafts[draft["architecture_id"]] = draft
    unknown = set(drafts) - set(ORDER)
    if unknown:
        raise SystemExit(f"Add {sorted(unknown)} to ORDER in render_cause_review.py")
    return [drafts[name] for name in ORDER if name in drafts]


def summary_rows(drafts: list[dict]) -> list[str]:
    rows = [
        "| Architecture | Causes | (target, STRIDE) entries | Distinct keys | direct | derived "
        "| scenario | easy | medium | hard | Boundary | Unsupported | Candidate chains |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    totals = [0] * 12
    for d in drafts:
        causes = d["causes"]
        entries = [(c["target"], k["category"]) for c in causes for k in c["categories"]]
        types = [c["evidence_type"] for c in causes]
        levels = [c["difficulty"]["level"] for c in causes]
        values = [
            len(causes), len(entries), len(set(entries)),
            types.count("direct"), types.count("derived"), types.count("scenario"),
            levels.count("easy"), levels.count("medium"), levels.count("hard"),
            len(d["boundary_cases"]), len(d["unsupported"]), len(d["candidate_chain_causes"]),
        ]
        totals = [a + b for a, b in zip(totals, values, strict=True)]
        rows.append(f"| {d['architecture_id']} | " + " | ".join(map(str, values)) + " |")
    rows.append("| **total** | " + " | ".join(f"**{v}**" for v in totals) + " |")
    return rows


def overview_table(draft: dict) -> list[str]:
    rows = [
        "| ID | Cause | Target | STRIDE | Evidence type | Difficulty |",
        "|---|---|---|---|---|---|",
    ]
    for c in draft["causes"]:
        for k in c["categories"]:
            rows.append(
                f"| {c['ref']} | `{c['cause_id']}` | {c['target']} | {k['category']} "
                f"| {c['evidence_type']} | {c['difficulty']['level']} |"
            )
    return rows


def cause_block(c: dict) -> list[str]:
    lines = [
        f"#### {c['ref']} `{c['cause_id']}`",
        "",
        f"- **Target:** {c['target']} ({c['target_kind']})",
        f"- **Root cause:** {c['root_cause']}",
        "- **Evidence:**",
        *[f"  - {line}" for line in evidence_lines(c["evidence"])],
        f"- **Evidence type:** {c['evidence_type']}",
        f"- **Justification:** {c['justification']}",
        f"- **Difficulty:** {c['difficulty']['level']}. {c['difficulty']['rationale']}",
        "- **STRIDE scenarios:**",
        *[f"  - `{k['category']}`: {k['scenario']}" for k in c["categories"]],
    ]
    if c.get("preconditions_not_stated"):
        lines.append("- **Preconditions not stated in the architecture:**")
        lines += [f"  - {p}" for p in c["preconditions_not_stated"]]
    if c.get("notes"):
        lines.append(f"- **Notes:** {c['notes']}")
    return [*lines, ""]


def boundary_table(draft: dict) -> list[str]:
    rows = ["| ID | Target | STRIDE | Based on | Note |", "|---|---|---|---|---|"]
    for b in draft["boundary_cases"]:
        based = "<br>".join(f"{code(e['path'])} = {code(e['observed'])}" for e in b["based_on"])
        rows.append(
            f"| {b['ref']} | {', '.join(b['targets'])} | {b['category']} | {based} "
            f"| {cell(b['note'])} |"
        )
    return rows


def unsupported_table(draft: dict) -> list[str]:
    rows = [
        "| ID | Target(s) | STRIDE | Claimed cause | Reason | Note |",
        "|---|---|---|---|---|---|",
    ]
    for u in draft["unsupported"]:
        targets = ", ".join(u["targets"])
        extra = ""
        if u.get("contradicting_evidence"):
            extra = " Contradicted by: " + "; ".join(
                f"{e['path']} = {json.dumps(e['observed'])}" for e in u["contradicting_evidence"]
            ) + "."
        rows.append(
            f"| {u['ref']} | {cell(targets)} | {u['category']} | {cell(u['claimed_cause'])} "
            f"| {u['reason']} | {cell(u['note'] + extra)} |"
        )
    return rows


def candidate_block(x: dict) -> list[str]:
    return [
        f"#### {x['ref']} `{x['cause_id']}`",
        "",
        f"- **Target / STRIDE:** {x['target']} / `{x['category']}`",
        f"- **Root cause:** {x['root_cause']}",
        f"- **Combines:** {', '.join(x['involves'])}",
        "- **Evidence:**",
        *[f"  - {line}" for line in evidence_lines(x["evidence"])],
        f"- **Evidence type / difficulty:** {x['evidence_type']} / {x['difficulty']['level']}. "
        f"{x['difficulty']['rationale']}",
        f"- **Why it is not in the confirmed list:** {x['overlap_note']}",
        "",
    ]


def render() -> str:
    drafts = load_drafts()
    operationalizations = {d["difficulty_operationalization"] for d in drafts}
    out = [
        "# V2 cause lists: review sheet (DRAFT)",
        "",
        "*Generated by `scripts/render_cause_review.py` from `benchmark_v2/draft/*.causes.json`. "
        "Do not edit this file; edit the JSON and regenerate.*",
        "",
        "**Status:** DRAFT, awaiting owner review (gate G2). Nothing here is frozen.",
        "",
        "## How to read this",
        "",
        "- **Confirmed causes** are the candidate ground truth. Each is backed by cited "
        "evidence that a test checks against the architecture file.",
        "- **Boundary cases** are exposure-only scenarios (policy P1). They are not required "
        "for recall; if a model predicts one it goes to `pending_review`.",
        "- **Unsupported** items are excluded, with a reason: `no_evidence` (silence is not "
        "evidence), `contradicted_by_config`, or `out_of_scope` (external entity).",
        "- **Candidate chain causes** combine several confirmed causes and overlap them. They "
        "are excluded by default and listed so you can decide.",
        "- The (target, STRIDE) pairs are the secondary coarse metric; the cause is the "
        "scoring unit.",
        "",
        "## Difficulty operationalization used",
        "",
        *[f"> {text}" for text in sorted(operationalizations)],
        "",
        "## Disclosure",
        "",
        *[f"> {d['provenance']['disclosure']}" for d in drafts[:1]],
        "",
        "## Summary",
        "",
        *summary_rows(drafts),
        "",
    ]
    for d in drafts:
        source = d["provenance"]["derived_from"]
        out += [
            f"## {d['architecture_id']}",
            "",
            f"Derived from `{source['file']}` (sha256 `{source['sha256_16']}`). "
            f"Version label: {d['gt_version']}.",
            "",
            "### Overview (one row per target and STRIDE category)",
            "",
            *overview_table(d),
            "",
            "### Confirmed causes",
            "",
        ]
        for c in d["causes"]:
            out += cause_block(c)
        out += ["### Boundary cases (policy P1)", "", *boundary_table(d), ""]
        out += ["### Unsupported (excluded)", "", *unsupported_table(d), ""]
        out += ["### Candidate chain causes (excluded by default)", ""]
        for x in d["candidate_chain_causes"]:
            out += candidate_block(x)
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the sheet is out of date")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != rendered:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date; run this script to regenerate.")
            return 1
        print("Review sheet is up to date.")
        return 0
    OUTPUT.write_text(rendered)
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(rendered.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
