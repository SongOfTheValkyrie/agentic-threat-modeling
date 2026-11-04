"""Blind annotation export for stored predictions (V2_SPEC.md sections 7.1 and 9).

The owner annotates every stored prediction with exactly one label, without
knowing which approach, run or file it came from. This module produces

* one **blind sheet** (CSV) per architecture, in a pseudo-random order that mixes
  all approaches, with an opaque identifier per row and empty label columns, and
* one **private mapping** (JSON) that joins each identifier back to the original
  prediction file, index, run and approach. The mapping must not be handed to the
  annotator and is written to a different directory.

Nothing here assigns a label or looks at the cause lists, except to name the
labels that are allowed for an architecture.

Order. For each architecture, rows are sorted by ``sha256(f"{seed}:{uid}")``. The
order depends only on the seed and on the identifiers, never on the order of the
input files, on a PRNG implementation, or on the Python version. The identifier
(``prediction_ids``) is a hash of the prediction's own run identity, position and
content.

The sheet carries the original ``target``, ``category``, ``description`` and
``mitigation`` text unchanged. It carries no model threat id, key, approach, model,
run index, timestamp, file name, trace reference or commit.
"""

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from src.evaluation.prediction_ids import assert_unique, prediction_uid
from src.evaluation.predictions import read_predictions

SEED = 20261103
ORDER_RULE = (
    "within each architecture, rows are sorted ascending by sha256 of the text "
    "'<seed>:<prediction identifier>'"
)
SCHEMA = "v2-annotation-export"
SCHEMA_VERSION = 1

# What the annotator sees. ``label``, ``unsure`` and ``note`` are the only columns to fill.
CONTENT_COLUMNS = ["pred_uid", "architecture", "target", "target_kind", "category",
                   "description", "mitigation"]
ANNOTATION_COLUMNS = ["label", "unsure", "note"]
BLIND_COLUMNS = CONTENT_COLUMNS + ANNOTATION_COLUMNS

# Labels besides the cause refs of the architecture (owner decision, V2_SPEC.md 7.1).
FIXED_LABELS = ("valid_additional", "unsupported", "pending_review")
UNSURE_VALUES = ("", "yes")

SHEET_NAME = "annotation_{architecture}.csv"
META_NAME = "annotation_export_meta.json"
README_NAME = "README.md"


class ExportError(Exception):
    """The export or its verification cannot proceed."""


@dataclass
class Source:
    """One stored prediction file that goes into the export."""

    path: Path
    sha256: str
    record: dict


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_sources(paths: list[str | Path]) -> list[Source]:
    sources = []
    for path in paths:
        path = Path(path)
        record = read_predictions(path)
        if record.get("schema_version") != 1:
            raise ExportError(
                f"{path}: unsupported prediction schema {record.get('schema_version')}"
            )
        sources.append(Source(path=path, sha256=file_sha256(path), record=record))
    if len({s.path.resolve() for s in sources}) != len(sources):
        raise ExportError("the same file was given twice")
    identities = [
        (s.record["architecture"], s.record["approach"], s.record["model"], s.record["run_index"])
        for s in sources
    ]
    if len(set(identities)) != len(identities):
        raise ExportError(
            "two input files describe the same architecture, approach, model and run"
        )
    return sources


def order_key(seed: int, uid: str) -> str:
    return hashlib.sha256(f"{seed}:{uid}".encode()).hexdigest()


def collect_items(sources: list[Source]) -> list[dict]:
    """All predictions of all sources, with private provenance, in no particular order."""
    items = []
    for source in sources:
        record = source.record
        for index, prediction in enumerate(record["predictions"]):
            items.append({
                "pred_uid": prediction_uid(record, index),
                "architecture": record["architecture"],
                "target": prediction["target"],
                "target_kind": prediction["target_kind"],
                "category": prediction["category"],
                "description": prediction["description"],
                "mitigation": prediction["mitigation"],
                "_source": source,
                "_index": index,
            })
    assert_unique([item["pred_uid"] for item in items])
    return items


def arrange(items: list[dict], seed: int) -> dict[str, list[dict]]:
    """Group by architecture and order each group by the documented rule."""
    by_architecture: dict[str, list[dict]] = {}
    for item in items:
        by_architecture.setdefault(item["architecture"], []).append(item)
    return {
        architecture: sorted(group, key=lambda i: order_key(seed, i["pred_uid"]))
        for architecture, group in sorted(by_architecture.items())
    }


def blind_row(item: dict) -> dict:
    row = {column: item[column] for column in CONTENT_COLUMNS}
    row.update({"label": "", "unsure": "", "note": ""})
    return row


def write_sheet(path: Path, rows: list[dict]) -> None:
    """Write a sheet, never overwriting an existing file."""
    with open(path, "x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BLIND_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_sheet(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != BLIND_COLUMNS:
            raise ExportError(f"{path}: columns are {reader.fieldnames}, expected {BLIND_COLUMNS}")
        return list(reader)


def allowed_labels(architecture: str, lists_dir: Path) -> list[str]:
    """Cause refs of the frozen list for this architecture, plus the fixed labels.

    Candidate chain refs and boundary or unsupported refs are not labels.
    """
    draft = json.loads((Path(lists_dir) / f"{architecture}.causes.json").read_text())
    return [c["ref"] for c in draft["causes"]] + list(FIXED_LABELS)


# --- annotation sheet checks ---------------------------------------------------------------


def check_annotations(rows: list[dict], allowed: list[str], require_complete: bool) -> list[str]:
    """Problems in a filled sheet: exactly one allowed label per row, valid ``unsure``."""
    problems = []
    seen: set[str] = set()
    for number, row in enumerate(rows, start=2):  # line 1 is the header
        uid = row["pred_uid"]
        if uid in seen:
            problems.append(f"line {number}: {uid} appears twice")
        seen.add(uid)
        label = row["label"].strip()
        if not label:
            if require_complete:
                problems.append(f"line {number}: {uid} has no label")
        elif label not in allowed:
            problems.append(
                f"line {number}: {uid} has label {row['label']!r}, which is not one label of "
                f"{allowed}"
            )
        if row["unsure"].strip().lower() not in UNSURE_VALUES:
            problems.append(
                f"line {number}: {uid} has unsure={row['unsure']!r}, expected empty or 'yes'"
            )
    return problems


def labels_by_uid(rows: list[dict]) -> dict[str, str]:
    """Label per identifier of a complete sheet (``unsure`` is kept separately)."""
    return {row["pred_uid"]: row["label"].strip() for row in rows}


def unsure_uids(rows: list[dict]) -> set[str]:
    return {row["pred_uid"] for row in rows if row["unsure"].strip().lower() == "yes"}


# --- private mapping --------------------------------------------------------------------------


def build_mapping(arranged: dict[str, list[dict]], sources: list[Source], seed: int) -> dict:
    source_entries = []
    for source in sorted(sources, key=lambda s: str(s.path)):
        record = source.record
        source_entries.append({
            "file": str(source.path),
            "sha256": source.sha256,
            "architecture": record["architecture"],
            "approach": record["approach"],
            "model": record["model"],
            "run_index": record["run_index"],
            "timestamp": record["timestamp"],
            "code": record.get("code"),
            "num_predictions": record["num_predictions"],
        })
    predictions = {}
    for architecture, group in arranged.items():
        for position, item in enumerate(group, start=1):
            record = item["_source"].record
            prediction = record["predictions"][item["_index"]]
            predictions[item["pred_uid"]] = {
                "architecture": architecture,
                "sheet": SHEET_NAME.format(architecture=architecture),
                "row_in_sheet": position,
                "approach": record["approach"],
                "model": record["model"],
                "run_index": record["run_index"],
                "file": str(item["_source"].path),
                "index_in_file": item["_index"],
                "threat_id": prediction["id"],
                "key": prediction["key"],
            }
    return {
        "schema": "v2-annotation-private-mapping",
        "schema_version": SCHEMA_VERSION,
        "private": "Do not give this file to the annotator.",
        "seed": seed,
        "order_rule": ORDER_RULE,
        "sources": source_entries,
        "predictions": predictions,
    }


# --- export --------------------------------------------------------------------------------------


def export(
    paths: list[str | Path],
    blind_dir: str | Path,
    mapping_path: str | Path,
    lists_dir: str | Path,
    gt_version: str,
    seed: int = SEED,
) -> dict:
    """Write the blind sheets, their metadata, and the private mapping. Never overwrites."""
    blind_dir, mapping_path = Path(blind_dir), Path(mapping_path)
    _assert_separate(blind_dir, mapping_path)
    sources = load_sources(paths)
    arranged = arrange(collect_items(sources), seed)

    blind_dir.mkdir(parents=True, exist_ok=True)
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    targets = [blind_dir / META_NAME, blind_dir / README_NAME, mapping_path] + [
        blind_dir / SHEET_NAME.format(architecture=a) for a in arranged
    ]
    existing = [str(t) for t in targets if t.exists()]
    if existing:
        raise ExportError(f"refusing to overwrite: {existing}")

    mapping = build_mapping(arranged, sources, seed)
    with open(mapping_path, "x", encoding="utf-8") as handle:
        json.dump(mapping, handle, indent=1, ensure_ascii=False, sort_keys=True)
        handle.write("\n")

    sheets = {}
    for architecture, group in arranged.items():
        sheet = blind_dir / SHEET_NAME.format(architecture=architecture)
        write_sheet(sheet, [blind_row(item) for item in group])
        sheets[architecture] = {
            "file": sheet.name, "rows": len(group), "sha256": file_sha256(sheet),
            "allowed_labels": allowed_labels(architecture, Path(lists_dir)),
        }

    meta = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "gt_version": gt_version,
        "seed": seed,
        "order_rule": ORDER_RULE,
        "columns": BLIND_COLUMNS,
        "total_rows": sum(s["rows"] for s in sheets.values()),
        "sheets": sheets,
        "mapping_sha256": file_sha256(mapping_path),
    }
    with open(blind_dir / META_NAME, "x", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    with open(blind_dir / README_NAME, "x", encoding="utf-8") as handle:
        handle.write(README_TEXT.format(gt_version=gt_version))
    return meta


def _assert_separate(blind_dir: Path, mapping_path: Path) -> None:
    blind, mapping = blind_dir.resolve(), mapping_path.resolve()
    if mapping == blind or blind in mapping.parents:
        raise ExportError(
            f"the private mapping {mapping} must not lie inside the blind export {blind}"
        )


# --- verification --------------------------------------------------------------------------------


def verify_export(
    blind_dir: str | Path, mapping_path: str | Path, seed: int | None = None
) -> tuple[list[str], dict]:
    """Check an export against the mapping and the (unchanged) source files.

    Returns (problems, stats). Checks: completeness of every source prediction, unique
    identifiers, unchanged source files, correct join back to the original prediction,
    reproducible order, sheet and mapping checksums, and blindness of the sheet files.
    """
    blind_dir, mapping_path = Path(blind_dir), Path(mapping_path)
    problems: list[str] = []
    meta = json.loads((blind_dir / META_NAME).read_text())
    mapping = json.loads(mapping_path.read_text())
    seed = meta["seed"] if seed is None else seed
    if meta["seed"] != seed or mapping["seed"] != seed:
        problems.append("seed differs between meta, mapping and the expected seed")
    if meta["mapping_sha256"] != file_sha256(mapping_path):
        problems.append("mapping checksum differs from the one recorded in the export")

    # Source files unchanged, and the sources re-read from disk.
    records: dict[str, dict] = {}
    for entry in mapping["sources"]:
        path = Path(entry["file"])
        if not path.exists():
            problems.append(f"source file missing: {path.name}")
            continue
        if file_sha256(path) != entry["sha256"]:
            problems.append(f"source file changed since the export: {path.name}")
        records[entry["file"]] = read_predictions(path)

    expected_total = sum(entry["num_predictions"] for entry in mapping["sources"])
    expected: dict[str, dict] = {}
    for file, record in records.items():
        for index, prediction in enumerate(record["predictions"]):
            expected[prediction_uid(record, index)] = {
                "architecture": record["architecture"], "prediction": prediction,
                "file": file, "index": index,
            }
    if len(expected) != sum(len(r["predictions"]) for r in records.values()):
        problems.append("identifiers computed from the sources collide")

    # The sheets.
    exported: dict[str, dict] = {}
    for architecture, info in meta["sheets"].items():
        sheet = blind_dir / info["file"]
        if file_sha256(sheet) != info["sha256"]:
            problems.append(f"{info['file']}: checksum differs from the one recorded")
        rows = read_sheet(sheet)
        if len(rows) != info["rows"]:
            problems.append(f"{info['file']}: {len(rows)} rows, meta says {info['rows']}")
        uids = [row["pred_uid"] for row in rows]
        if uids != sorted(uids, key=lambda u: order_key(seed, u)):
            problems.append(f"{info['file']}: row order does not follow the documented rule")
        for position, row in enumerate(rows, start=1):
            uid = row["pred_uid"]
            if uid in exported:
                problems.append(f"{uid} appears in more than one row")
            exported[uid] = row
            origin = expected.get(uid)
            if origin is None:
                problems.append(f"{uid}: not a prediction of any source file")
                continue
            if origin["architecture"] != architecture:
                problems.append(
                    f"{uid}: in the sheet of {architecture} but predicted on "
                    f"{origin['architecture']}"
                )
            for column in ("target", "target_kind", "category", "description", "mitigation"):
                if row[column] != origin["prediction"][column]:
                    problems.append(f"{uid}: {column} differs from the stored prediction")
            if any(row[c] for c in ANNOTATION_COLUMNS):
                problems.append(f"{uid}: an annotation column is filled in a fresh export")
            link = mapping["predictions"].get(uid)
            if link is None:
                problems.append(f"{uid}: missing in the mapping")
            elif (link["file"], link["index_in_file"], link["row_in_sheet"]) != (
                origin["file"], origin["index"], position
            ):
                problems.append(f"{uid}: the mapping points to another prediction or row")

    missing = sorted(set(expected) - set(exported))
    extra = sorted(set(exported) - set(expected))
    if missing:
        problems.append(f"{len(missing)} stored prediction(s) are not in the export")
    if extra:
        problems.append(f"{len(extra)} exported row(s) are not stored predictions")
    if len(exported) != expected_total:
        problems.append(f"{len(exported)} rows exported, {expected_total} predictions stored")
    if set(mapping["predictions"]) != set(expected):
        problems.append("the mapping does not cover exactly the stored predictions")

    problems += blindness_problems(blind_dir, mapping)
    stats = {
        "stored_predictions": expected_total,
        "exported_rows": len(exported),
        "unique_identifiers": len(set(exported)),
        "rows_per_architecture": {a: i["rows"] for a, i in meta["sheets"].items()},
        "source_files": len(mapping["sources"]),
    }
    return problems, stats


def private_values(mapping: dict) -> tuple[set[str], set[str]]:
    """Values that identify approach, run, file or trace, and the model threat ids apart.

    Model threat ids are built from target and category plus a counter, so they are checked
    only in metadata and instructions, not against the content columns.
    """
    secrets: set[str] = set()
    for entry in mapping["sources"]:
        secrets |= {entry["approach"], entry["model"], entry["timestamp"], Path(entry["file"]).name,
                    entry["file"]}
        commit = (entry.get("code") or {}).get("commit")
        if commit:
            secrets.add(commit)
    threat_ids = {str(link["threat_id"]) for link in mapping["predictions"].values()}
    return {s for s in secrets if s}, threat_ids


def blindness_problems(blind_dir: Path, mapping: dict) -> list[str]:
    """The files handed to the annotator must hold no approach, run, file or trace data.

    The free text of a prediction is not scanned here: it is copied unchanged and may
    contain any word. Everything else (columns, identifiers, metadata, instructions) must
    be free of the private values.
    """
    problems = []
    secrets, threat_ids = private_values(mapping)
    for name in (META_NAME, README_NAME):
        text = (blind_dir / name).read_text()
        for secret in sorted(secrets | threat_ids):
            if secret in text:
                problems.append(f"{name} contains private value {secret!r}")
    for path in sorted(blind_dir.glob("annotation_*.csv")):
        for row in read_sheet(path):
            for column in ("pred_uid", "architecture", "target", "target_kind", "category"):
                for secret in secrets:
                    if secret in row[column]:
                        problems.append(
                            f"{path.name}: column {column} contains private value {secret!r}"
                        )
    if list(Path(blind_dir).glob("*mapping*")):
        problems.append("a mapping file lies in the blind export directory")
    return problems


README_TEXT = """# Blind annotation sheets (GT {gt_version})

Annotate every row of the sheets. Do not open `annotation_private/` or any
file named `*mapping*`: it would unblind the sheets.

Columns to fill in:

- `label`: exactly one of
  - a cause ref of the architecture (listed per sheet in
    `annotation_export_meta.json` under `allowed_labels`; the causes are described in
    `benchmark_v2/v2.0/REVIEW.md`),
  - `valid_additional`: a plausible, evidenced finding that is not in the cause list,
  - `unsupported`: not supported by the architecture,
  - `pending_review`: needs a later decision.
- `unsure`: enter `yes` if you are not sure about the label, otherwise leave empty.
- `note`: optional free text, for example a short description of a proposed new cause.

All other columns are copied unchanged from the stored prediction. Rows appear in a
pseudo-random order that mixes all approaches. Row order and the identifier carry no
information.
"""
