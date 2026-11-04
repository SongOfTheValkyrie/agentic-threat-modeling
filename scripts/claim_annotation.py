#!/usr/bin/env python3
"""Claim-level annotation tooling (see benchmark_v2/annotation/CLAIM_SCORING.md).

Run from the repository root. The tool assigns no label. It exports the pre-seeded claim
sheets from the private mapping, checks filled sheets, migrates the first single-label
sheet, draws the repeat sample and computes the agreement of two passes.

Commands::

    export         write the pre-seeded claim sheets (same ids and order as the first export)
    verify         check a fresh claim export against the mapping and the prediction files
    check          validate a filled claim sheet (rules V1 to V12)
    migrate        move a filled single-label sheet into the claim format
    repeat-sample  draw the stratified, seeded sample for the repeat annotation
    kappa          agreement of the first and the repeat pass
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation import annotation_export as ax  # noqa: E402
from src.evaluation import claim_sheet as cs  # noqa: E402
from src.evaluation.claims import reliability, repeat_sample  # noqa: E402

LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
DEV_CASES = ROOT / "benchmark_v2" / "annotation" / "dev_cases_protocol_v1.json"
DEFAULT_DIR = "benchmark_v2/annotation/blind_claims"
DEFAULT_MAPPING = "annotation_private/mapping.json"
REPEAT_SEED = 20261104


def _gt_version() -> str:
    return json.loads((LISTS_DIR / "MANIFEST.json").read_text())["gt_version"]


def _template(directory: str, architecture: str) -> list[dict]:
    name = cs.CLAIM_SHEET_NAME.format(architecture=architecture)
    return cs.read_claim_sheet(Path(directory) / name)


def _problems(args, filled_path: str, require_complete: bool) -> tuple[list[str], list[dict]]:
    rows = cs.read_claim_sheet(Path(filled_path))
    causes = cs.cause_set(args.architecture, LISTS_DIR)
    problems = cs.validate_claim_rows(
        rows, _template(args.template_dir, args.architecture), causes,
        ROOT / "benchmark" / f"{args.architecture}.json", require_complete,
    )
    return problems, rows


def cmd_export(args) -> int:
    meta = cs.export_claim_sheets(args.blind_dir, args.mapping, LISTS_DIR, _gt_version())
    print(f"Wrote claim sheets for {meta['total_predictions']} predictions to {args.blind_dir}.")
    for info in meta["sheets"].values():
        print(f"  {info['file']}: {info['predictions']} predictions")
    return 0


def cmd_verify(args) -> int:
    problems, stats = cs.verify_claim_export(args.blind_dir, args.mapping)
    print(json.dumps(stats, indent=2))
    for problem in problems:
        print(f"PROBLEM: {problem}")
    print("Export verified." if not problems else f"{len(problems)} problem(s).")
    return 1 if problems else 0


def cmd_check(args) -> int:
    problems, rows = _problems(args, args.filled, args.complete)
    labelled = sum(1 for r in rows if r["claim_label"].strip())
    print(f"{labelled} labelled claim rows of {len(rows)}; {len(problems)} problem(s).")
    for problem in problems:
        print(f"  {problem}")
    return 1 if problems else 0


def cmd_migrate(args) -> int:
    old = ax.read_sheet(Path(args.old))
    template = _template(args.template_dir, args.architecture)
    migrated, report = cs.migrate_old_sheet(old, template)
    cs.write_claim_sheet(Path(args.out), migrated)
    print(f"Migrated {report['migrated']} labelled predictions, {report['unlabelled']} unlabelled.")
    if report["needs_reason_code"]:
        print(f"{len(report['needs_reason_code'])} unsupported claim(s) need a reason_code "
              "(nothing was invented):")
        for uid in report["needs_reason_code"]:
            print(f"  {uid}")
    return 0


def cmd_repeat_sample(args) -> int:
    problems, rows = _problems(args, args.filled, require_complete=True)
    if problems:
        print("The first pass is not complete and valid:")
        for problem in problems[:20]:
            print(f"  {problem}")
        return 1
    causes = cs.cause_set(args.architecture, LISTS_DIR)
    dev = json.loads(DEV_CASES.read_text())
    excluded = {c["pred_uid"] for c in dev["cases"] if dev["architecture"] == args.architecture}
    sample = repeat_sample(
        cs.rows_to_claims(rows), causes, excluded, args.seed, args.first_pass_finished, args.size,
    )
    sample["architecture"] = args.architecture
    Path(args.out).write_text(json.dumps(sample, indent=1) + "\n")
    cs.write_claim_sheet(
        Path(args.sheet_out), cs.repeat_sheet_rows(_template(args.template_dir, args.architecture),
                                                   sample["selected"]),
    )
    print(f"Sample of {len(sample['selected'])} (eligible {sample['eligible']}), strata "
          f"{sample['strata_selected']}. Second pass not before {sample['not_before']}.")
    return 0


def cmd_kappa(args) -> int:
    sample = json.loads(Path(args.sample).read_text())
    if datetime.fromisoformat(args.pass2_finished) < datetime.fromisoformat(sample["not_before"]):
        print(f"The second pass finished before {sample['not_before']}: less than 24 hours "
              "after the first pass.")
        return 1
    problems1, rows1 = _problems(args, args.pass1, require_complete=True)
    problems2, rows2 = _problems(args, args.pass2, require_complete=True)
    if problems1 or problems2:
        print("Both passes must be complete and valid:")
        for problem in (problems1 + problems2)[:20]:
            print(f"  {problem}")
        return 1
    chosen = set(sample["selected"])
    causes = cs.cause_set(args.architecture, LISTS_DIR)
    first = [c for c in cs.rows_to_claims(rows1) if c.pred_uid in chosen]
    second = cs.rows_to_claims(rows2)
    result = reliability(first, second, causes.labels())
    print(json.dumps(result, indent=1, default=list))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, mapping=False, template=False):
        if mapping:
            p.add_argument("--mapping", default=DEFAULT_MAPPING)
        if template:
            p.add_argument("--architecture", required=True)
            p.add_argument("--template-dir", default=DEFAULT_DIR,
                           help="directory of the unlabelled claim export")

    p = sub.add_parser("export")
    p.add_argument("--blind-dir", default=DEFAULT_DIR)
    common(p, mapping=True)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("verify")
    p.add_argument("--blind-dir", default=DEFAULT_DIR)
    common(p, mapping=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("check")
    common(p, template=True)
    p.add_argument("--filled", required=True)
    p.add_argument("--complete", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("migrate")
    common(p, template=True)
    p.add_argument("--old", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("repeat-sample")
    common(p, template=True)
    p.add_argument("--filled", required=True)
    p.add_argument("--first-pass-finished", required=True, help="ISO timestamp of the first pass")
    p.add_argument("--seed", type=int, default=REPEAT_SEED)
    p.add_argument("--size", type=int, default=20)
    p.add_argument("--out", required=True, help="sample file (JSON)")
    p.add_argument("--sheet-out", required=True, help="blank claim sheet for the second pass")
    p.set_defaults(func=cmd_repeat_sample)

    p = sub.add_parser("kappa")
    common(p, template=True)
    p.add_argument("--pass1", required=True)
    p.add_argument("--pass2", required=True)
    p.add_argument("--sample", required=True)
    p.add_argument("--pass2-finished", required=True)
    p.set_defaults(func=cmd_kappa)

    args = parser.parse_args()
    try:
        return args.func(args)
    except ax.ExportError as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
