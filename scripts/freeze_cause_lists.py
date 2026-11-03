#!/usr/bin/env python3
"""Record or verify the checksums of the frozen V2 cause lists.

The manifest ``benchmark_v2/v2.0/MANIFEST.json`` holds, for every cause list, the
SHA-256 of the file, the SHA-256 of the architecture file it was derived from, and
the recall denominators. ``--write`` creates it once and refuses to overwrite it:
a frozen list is never edited in place, a change is a new version (V2.1).

Usage (from the repository root)::

    python scripts/freeze_cause_lists.py --write     # first and only time, at the freeze
    python scripts/freeze_cause_lists.py --check     # exit 1 if a list or architecture changed
"""

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
MANIFEST = LISTS_DIR / "MANIFEST.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_manifest(directory: Path = LISTS_DIR, root: Path = ROOT, frozen_on: str = "") -> dict:
    lists = {}
    gt_versions = set()
    for path in sorted(directory.glob("*.causes.json")):
        draft = json.loads(path.read_text())
        source = draft["provenance"]["derived_from"]
        architecture = root / source["file"]
        gt_versions.add(draft["gt_version"])
        lists[path.name] = {
            "sha256": sha256(path),
            "architecture_file": source["file"],
            "architecture_sha256": sha256(architecture),
            "causes": len(draft["causes"]),
            "threat_cause_recall_denominator": len(draft["recall_sets"]["threat_cause_recall"]),
            "security_control_gap_recall_denominator": len(
                draft["recall_sets"]["security_control_gap_recall"]
            ),
        }
    if len(gt_versions) != 1:
        raise SystemExit(f"cause lists disagree on the ground-truth version: {gt_versions}")
    return {
        "gt_version": gt_versions.pop(),
        "frozen_on": frozen_on,
        "algorithm": "sha256 over the file bytes",
        "note": "A frozen list is never edited in place. A change is a new version (V2.1).",
        "cause_lists": lists,
    }


def verify(
    directory: Path = LISTS_DIR, root: Path = ROOT, manifest_path: Path = MANIFEST
) -> list[str]:
    """Return the differences between the manifest and the files on disk."""
    recorded = json.loads(manifest_path.read_text())
    current = compute_manifest(directory, root, recorded["frozen_on"])
    problems = []
    if recorded["gt_version"] != current["gt_version"]:
        problems.append(f"gt_version {recorded['gt_version']} != {current['gt_version']}")
    for name in sorted(set(recorded["cause_lists"]) | set(current["cause_lists"])):
        old, new = recorded["cause_lists"].get(name), current["cause_lists"].get(name)
        if old is None or new is None:
            problems.append(f"{name}: present on one side only")
            continue
        for field in old:
            if old[field] != new.get(field):
                problems.append(f"{name}: {field} changed")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--date", default=date.today().isoformat(),
                        help="freeze date recorded with --write (default: today)")
    args = parser.parse_args()

    if args.write:
        if MANIFEST.exists():
            print(f"{MANIFEST.relative_to(ROOT)} exists. A frozen list is not re-frozen.")
            return 1
        manifest = compute_manifest(frozen_on=args.date)
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Wrote {MANIFEST.relative_to(ROOT)} for {len(manifest['cause_lists'])} lists.")
        return 0

    problems = verify()
    for problem in problems:
        print(f"MISMATCH: {problem}")
    print("Frozen lists match the manifest." if not problems else "Frozen lists changed.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
