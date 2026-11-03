#!/usr/bin/env python3
"""Blind annotation export for stored predictions (see src/evaluation/annotation_export.py).

Run from the repository root, because the private mapping stores the prediction file
paths as given on the command line.

Commands::

    export     write blind sheets, their metadata, and the private mapping
    verify     check an export against the mapping and the unchanged prediction files
    check      check a filled sheet: exactly one allowed label per row
    example    write a small export of synthetic predictions (for documentation)

Example::

    python scripts/export_annotation_sheet.py export \\
        --predictions results/predictions/<file>.json ... \\
        --blind-dir benchmark_v2/annotation/blind \\
        --mapping annotation_private/mapping.json
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation import annotation_export as ax  # noqa: E402

LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
DEFAULT_BLIND_DIR = "benchmark_v2/annotation/blind"
DEFAULT_MAPPING = "annotation_private/mapping.json"


def _gt_version() -> str:
    manifest = json.loads((LISTS_DIR / "MANIFEST.json").read_text())
    return manifest["gt_version"]


# --- synthetic example -------------------------------------------------------------------------

# Clearly artificial content. Threat ids and metadata carry approach hints on purpose, to show
# that none of them reaches the blind sheet.
_C, _F = "component", "data_flow"
_SYNTHETIC = {
    "rag": [
        ("api", _C, "spoofing", "SYNTHETIC: weak session handling on the api."),
        ("shared_db", _C, "information_disclosure", "SYNTHETIC: rows readable across tenants."),
        ("user_to_api", _F, "tampering", "SYNTHETIC: request body can be altered."),
        ("object_store", _C, "information_disclosure",
         'SYNTHETIC: files readable, with a comma, and "quotes".'),
        ("admin_portal", _C, "elevation_of_privilege",
         "SYNTHETIC: admin role is broad.\nSecond line of the same text."),
    ],
    "agent_pev": [
        ("api", _C, "elevation_of_privilege", "SYNTHETIC: caller acts beyond its role."),
        ("shared_db", _C, "information_disclosure",
         "SYNTHETIC: rows readable across tenants (other wording)."),
        ("document_service", _C, "tampering", "SYNTHETIC: objects can be changed by others."),
        ("admin_portal", _C, "spoofing", "SYNTHETIC: portal login can be impersonated."),
    ],
    "agent_pev_noplan": [
        ("api", _C, "denial_of_service", "SYNTHETIC: no request limits."),
        ("object_store", _C, "tampering", "SYNTHETIC: files can be overwritten."),
        ("document_service", _C, "information_disclosure",
         "SYNTHETIC: documents served without ownership check."),
        ("shared_db", _C, "tampering", "SYNTHETIC: rows changed across tenants."),
        ("api_to_db", _F, "information_disclosure",
         "SYNTHETIC: unéxpected ünicode text – kept as is."),
    ],
}


def write_synthetic_sources(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for run_index, (approach, items) in enumerate(_SYNTHETIC.items()):
        record = {
            "schema_version": 1,
            "timestamp": f"2026-01-01T00:0{run_index}:00+00:00",
            "approach": approach,
            "model": "synthetic-model",
            "architecture": "multi_tenant_saas",
            "run_index": 0,
            "code": {"commit": "0" * 39 + str(run_index + 1), "dirty": False},
            "num_predictions": len(items),
            "predictions": [
                {
                    "id": f"{approach}-threat-{i}",
                    "target": target,
                    "target_kind": kind,
                    "category": category,
                    "description": text,
                    "mitigation": f"SYNTHETIC mitigation {i}",
                    "key": f"{target}:{category}",
                }
                for i, (target, kind, category, text) in enumerate(items)
            ],
        }
        path = directory / f"multi_tenant_saas_{approach}_synthetic_run0.json"
        path.write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n")
        paths.append(path)
    return paths


def cmd_example(args) -> int:
    out = Path(args.out)
    sources = write_synthetic_sources(out / "synthetic_sources")
    # Relative paths, so the mapping of the example does not depend on this machine.
    relative = [p.relative_to(ROOT) if p.is_relative_to(ROOT) else p for p in sources]
    meta = ax.export(
        relative, out / "blind", out / "private_mapping_of_the_example.json",
        LISTS_DIR, _gt_version(),
    )
    print(f"Wrote a synthetic example with {meta['total_rows']} rows to {out}")
    return 0


# --- export / verify / check -------------------------------------------------------------------


def cmd_export(args) -> int:
    meta = ax.export(args.predictions, args.blind_dir, args.mapping, LISTS_DIR, _gt_version(),
                     seed=args.seed)
    print(f"Wrote {meta['total_rows']} rows to {args.blind_dir} (seed {meta['seed']}).")
    for info in meta["sheets"].values():
        print(f"  {info['file']}: {info['rows']} rows")
    print(f"Private mapping: {args.mapping} (keep it away from the annotator).")
    return 0


def cmd_verify(args) -> int:
    problems, stats = ax.verify_export(args.blind_dir, args.mapping)
    print(json.dumps(stats, indent=2))
    for problem in problems:
        print(f"PROBLEM: {problem}")
    print("Export verified." if not problems else f"{len(problems)} problem(s).")
    return 1 if problems else 0


def cmd_check(args) -> int:
    meta = json.loads((Path(args.blind_dir) / ax.META_NAME).read_text())
    status = 0
    for info in meta["sheets"].values():
        rows = ax.read_sheet(Path(args.sheet_dir) / info["file"])
        problems = ax.check_annotations(rows, info["allowed_labels"], args.complete)
        labelled = sum(1 for r in rows if r["label"].strip())
        print(f"{info['file']}: {labelled}/{len(rows)} labelled, {len(problems)} problem(s)")
        for problem in problems:
            print(f"  {problem}")
        status |= bool(problems)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="write the blind sheets and the private mapping")
    export.add_argument("--predictions", nargs="+", required=True)
    export.add_argument("--blind-dir", default=DEFAULT_BLIND_DIR)
    export.add_argument("--mapping", default=DEFAULT_MAPPING)
    export.add_argument("--seed", type=int, default=ax.SEED)
    export.set_defaults(func=cmd_export)

    verify = sub.add_parser("verify", help="verify an export")
    verify.add_argument("--blind-dir", default=DEFAULT_BLIND_DIR)
    verify.add_argument("--mapping", default=DEFAULT_MAPPING)
    verify.set_defaults(func=cmd_verify)

    check = sub.add_parser("check", help="check the labels of filled sheets")
    check.add_argument("--blind-dir", default=DEFAULT_BLIND_DIR, help="holds the metadata")
    check.add_argument("--sheet-dir", default=DEFAULT_BLIND_DIR, help="holds the filled sheets")
    check.add_argument("--complete", action="store_true", help="every row needs a label")
    check.set_defaults(func=cmd_check)

    example = sub.add_parser("example", help="write a synthetic example export")
    example.add_argument("--out", default="benchmark_v2/annotation/example")
    example.set_defaults(func=cmd_example)

    args = parser.parse_args()
    try:
        return args.func(args)
    except ax.ExportError as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
