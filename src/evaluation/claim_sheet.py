"""The claim-level annotation sheet (V2_SPEC.md D27; CLAIM_SCORING.md section 12).

One long-format CSV per architecture, one pre-seeded empty claim row per prediction.
Another claim of a prediction is a copy of its row with the next ``claim_no``.

This module exports the sheets from an existing private mapping (same identifiers, same
order as the first export), reads them, validates a filled sheet against rules V1 to V12,
migrates a filled single-label sheet, and builds the sheet of the repeat annotation. It
assigns no label.
"""

import csv
import json
from pathlib import Path

from src.evaluation import annotation_export as ax
from src.evaluation.claims import REASON_CODES, UN, VA, CauseSet, Claim
from src.evaluation.predictions import read_predictions

PROTOCOL_VERSION = "1.1"
SCHEMA = "v2-annotation-claim-export"
SCHEMA_VERSION = 2

CLAIM_COLUMNS = ax.CONTENT_COLUMNS + [
    "claim_no", "claim_label", "reason_code", "claim_text", "evidence_refs", "candidate_id",
    "plausible_causes", "rationale", "unsure", "target_judgement", "stride_judgement",
]
ANNOTATION_FIELDS = CLAIM_COLUMNS[len(ax.CONTENT_COLUMNS) + 1:]  # everything after claim_no
CLAIM_SHEET_NAME = "annotation_claims_{architecture}.csv"
CLAIM_META_NAME = "annotation_claims_meta.json"
CLAIM_README_NAME = "README.md"
JUDGEMENT_VALUES = ("", "ok", "deviates")


# --- reading and writing ---------------------------------------------------------------------


def read_claim_sheet(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != CLAIM_COLUMNS:
            raise ax.ExportError(
                f"{path}: columns are {reader.fieldnames}, expected {CLAIM_COLUMNS}"
            )
        return list(reader)


def write_claim_sheet(path: Path, rows: list[dict]) -> None:
    """Write a sheet, never overwriting an existing file."""
    with open(path, "x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CLAIM_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def blank_row(content: dict, claim_no: int = 1) -> dict:
    row = {column: content[column] for column in ax.CONTENT_COLUMNS}
    row.update({column: "" for column in ANNOTATION_FIELDS})
    row["claim_no"] = str(claim_no)
    return row


def split_list(text: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in text.split(";") if part.strip())


def rows_to_claims(rows: list[dict]) -> list[Claim]:
    """Claims of all labelled rows. Unlabelled rows are skipped."""
    claims = []
    for row in rows:
        if not row["claim_label"].strip():
            continue
        claims.append(Claim(
            pred_uid=row["pred_uid"], claim_no=int(row["claim_no"]),
            label=row["claim_label"].strip(), unsure=row["unsure"].strip().lower() == "yes",
            candidate_id=row["candidate_id"].strip(),
            plausible_causes=split_list(row["plausible_causes"]),
            rationale=row["rationale"], evidence_refs=split_list(row["evidence_refs"]),
            reason_code=row["reason_code"].strip(), claim_text=row["claim_text"],
        ))
    return claims


# --- export from the existing private mapping ------------------------------------------------


def export_claim_sheets(
    blind_dir: str | Path, mapping_path: str | Path, lists_dir: str | Path, gt_version: str,
) -> dict:
    """Pre-seeded claim sheets with the same identifiers and order as the first export.

    The private mapping is only read. It must still describe unchanged prediction files.
    """
    blind_dir, mapping_path = Path(blind_dir), Path(mapping_path)
    ax._assert_separate(blind_dir, mapping_path)
    mapping = json.loads(mapping_path.read_text())
    sources = ax.load_sources([entry["file"] for entry in mapping["sources"]])
    for source, entry in zip(
        sorted(sources, key=lambda s: str(s.path)), mapping["sources"], strict=True
    ):
        if source.sha256 != entry["sha256"]:
            raise ax.ExportError(f"{source.path.name} changed since the first export")
    arranged = ax.arrange(ax.collect_items(sources), mapping["seed"])
    for architecture, group in arranged.items():
        for position, item in enumerate(group, start=1):
            link = mapping["predictions"].get(item["pred_uid"])
            if link is None or (link["architecture"], link["row_in_sheet"]) != (
                architecture, position
            ):
                raise ax.ExportError(f"{item['pred_uid']} does not match the mapping")

    blind_dir.mkdir(parents=True, exist_ok=True)
    targets = [blind_dir / CLAIM_META_NAME, blind_dir / CLAIM_README_NAME] + [
        blind_dir / CLAIM_SHEET_NAME.format(architecture=a) for a in arranged
    ]
    existing = [str(t) for t in targets if t.exists()]
    if existing:
        raise ax.ExportError(f"refusing to overwrite: {existing}")

    sheets = {}
    for architecture, group in arranged.items():
        sheet = blind_dir / CLAIM_SHEET_NAME.format(architecture=architecture)
        write_claim_sheet(sheet, [blank_row(item) for item in group])
        causes = _cause_set(architecture, Path(lists_dir))
        sheets[architecture] = {
            "file": sheet.name, "predictions": len(group), "sha256": ax.file_sha256(sheet),
            "allowed_labels": causes.labels(),
        }
    meta = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "protocol_version": PROTOCOL_VERSION,
        "gt_version": gt_version, "seed": mapping["seed"], "order_rule": ax.ORDER_RULE,
        "columns": CLAIM_COLUMNS, "reason_codes": list(REASON_CODES),
        "total_predictions": sum(s["predictions"] for s in sheets.values()),
        "sheets": sheets, "mapping_sha256": ax.file_sha256(mapping_path),
    }
    with open(blind_dir / CLAIM_META_NAME, "x", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    with open(blind_dir / CLAIM_README_NAME, "x", encoding="utf-8") as handle:
        handle.write(CLAIM_README.format(gt_version=gt_version, protocol=PROTOCOL_VERSION))
    return meta


def _cause_set(architecture: str, lists_dir: Path) -> CauseSet:
    return CauseSet.from_draft(json.loads((lists_dir / f"{architecture}.causes.json").read_text()))


def cause_set(architecture: str, lists_dir: str | Path) -> CauseSet:
    return _cause_set(architecture, Path(lists_dir))


# --- verification of a fresh export ----------------------------------------------------------


def verify_claim_export(blind_dir: str | Path, mapping_path: str | Path) -> tuple[list[str], dict]:
    """Check a fresh (unlabelled) claim export against the mapping and the source files."""
    blind_dir, mapping_path = Path(blind_dir), Path(mapping_path)
    problems: list[str] = []
    meta = json.loads((blind_dir / CLAIM_META_NAME).read_text())
    mapping = json.loads(mapping_path.read_text())
    if meta["mapping_sha256"] != ax.file_sha256(mapping_path):
        problems.append("mapping checksum differs from the one recorded in the export")
    if meta["seed"] != mapping["seed"]:
        problems.append("seed differs between export and mapping")

    expected: dict[str, dict] = {}
    for entry in mapping["sources"]:
        path = Path(entry["file"])
        if ax.file_sha256(path) != entry["sha256"]:
            problems.append(f"source file changed since the export: {path.name}")
            continue
        record = read_predictions(path)
        for index, prediction in enumerate(record["predictions"]):
            expected[ax.prediction_uid(record, index)] = {
                "architecture": record["architecture"], "prediction": prediction,
                "file": entry["file"], "index": index,
            }
    seen: dict[str, dict] = {}
    for architecture, info in meta["sheets"].items():
        sheet = blind_dir / info["file"]
        if ax.file_sha256(sheet) != info["sha256"]:
            problems.append(f"{info['file']}: checksum differs from the one recorded")
        rows = read_claim_sheet(sheet)
        uids = [row["pred_uid"] for row in rows]
        if len(rows) != info["predictions"]:
            problems.append(f"{info['file']}: {len(rows)} rows, meta says {info['predictions']}")
        if uids != sorted(uids, key=lambda u: ax.order_key(meta["seed"], u)):
            problems.append(f"{info['file']}: row order does not follow the documented rule")
        for position, row in enumerate(rows, start=1):
            uid = row["pred_uid"]
            if uid in seen:
                problems.append(f"{uid} appears in more than one row")
            seen[uid] = row
            origin = expected.get(uid)
            if origin is None:
                problems.append(f"{uid}: not a prediction of any source file")
                continue
            if origin["architecture"] != architecture:
                problems.append(f"{uid}: in the sheet of the wrong architecture")
            for column in ("target", "target_kind", "category", "description", "mitigation"):
                if row[column] != origin["prediction"][column]:
                    problems.append(f"{uid}: {column} differs from the stored prediction")
            if row["claim_no"] != "1" or any(row[c] for c in ANNOTATION_FIELDS):
                problems.append(f"{uid}: a fresh export must hold one empty claim row")
            link = mapping["predictions"].get(uid)
            if link is None or (link["file"], link["index_in_file"], link["row_in_sheet"]) != (
                origin["file"], origin["index"], position
            ):
                problems.append(f"{uid}: the mapping points to another prediction or row")
    if set(expected) != set(seen):
        problems.append(
            f"{len(set(expected) - set(seen))} stored prediction(s) missing and "
            f"{len(set(seen) - set(expected))} unknown row(s)"
        )
    problems += claim_blindness_problems(blind_dir, mapping)
    stats = {
        "stored_predictions": len(expected), "claim_rows": len(seen),
        "unique_identifiers": len(set(seen)),
        "predictions_per_architecture": {a: i["predictions"] for a, i in meta["sheets"].items()},
    }
    return problems, stats


def claim_blindness_problems(blind_dir: Path, mapping: dict) -> list[str]:
    """No approach, run, file or trace data in the claim export files."""
    problems = []
    secrets, threat_ids = ax.private_values(mapping)
    for name in (CLAIM_META_NAME, CLAIM_README_NAME):
        text = (blind_dir / name).read_text()
        for secret in sorted(secrets | threat_ids):
            if secret in text:
                problems.append(f"{name} contains private value {secret!r}")
    for path in sorted(blind_dir.glob("annotation_claims_*.csv")):
        for row in read_claim_sheet(path):
            for column in ("pred_uid", "architecture", "target", "target_kind", "category"):
                for secret in secrets:
                    if secret in row[column]:
                        problems.append(
                            f"{path.name}: column {column} contains private value {secret!r}"
                        )
    if list(Path(blind_dir).glob("*mapping*")):
        problems.append("a mapping file lies in the blind export directory")
    return problems


# --- validation of a filled sheet (rules V1 to V12) ------------------------------------------


def resolve_path(architecture: dict, path: str):
    """Follow ``components.<id>.<field>[.config.<key>]`` or ``data_flows.<id>.<field>``."""
    section, element_id, *rest = path.split(".")
    value = next(item for item in architecture[section] if item["id"] == element_id)
    for key in rest:
        value = value[key]
    return value


def is_standard_match(row: dict, n_claims: int, causes: CauseSet) -> bool:
    """A cause claim that needs no individual reasoning (P6)."""
    ref = row["claim_label"].strip()
    if ref not in causes.refs or n_claims != 1 or row["unsure"].strip():
        return False
    if row["target_judgement"].strip() or row["stride_judgement"].strip():
        return False
    cause = causes.causes[ref]
    if row["target"] != cause["target"]:
        return False
    categories = [k["category"] for k in cause["categories"]]
    return not categories or row["category"] in categories


def validate_claim_rows(
    rows: list[dict],
    template_rows: list[dict],
    causes: CauseSet,
    architecture_file: str | Path,
    require_complete: bool = False,
) -> list[str]:
    """Problems in a filled claim sheet. ``template_rows`` is the unlabelled export."""
    problems: list[str] = []
    template = {r["pred_uid"]: r for r in template_rows}
    architecture = json.loads(Path(architecture_file).read_text())
    allowed = causes.labels()

    def where(number: int, row: dict) -> str:
        return f"line {number} ({row.get('pred_uid', '?')})"

    by_uid: dict[str, list[tuple[int, dict]]] = {}
    for number, row in enumerate(rows, start=2):
        uid = row["pred_uid"]
        if uid not in template:
            problems.append(f"{where(number, row)}: not a prediction of this export")
            continue
        for column in ax.CONTENT_COLUMNS:
            if row[column] != template[uid][column]:
                problems.append(f"{where(number, row)}: {column} differs from the export (V2)")
        by_uid.setdefault(uid, []).append((number, row))

    for uid in template:
        if uid not in by_uid:
            problems.append(f"{uid}: no claim row (V1)")
            continue
        entries = by_uid[uid]
        numbers = [e[1]["claim_no"].strip() for e in entries]
        if not all(n.isdigit() for n in numbers) or sorted(map(int, numbers)) != list(
            range(1, len(entries) + 1)
        ):
            problems.append(
                f"{uid}: claim_no must be 1..{len(entries)} without gaps or repeats (V1)"
            )
        labelled = [(n, r) for n, r in entries if r["claim_label"].strip()]
        for number, row in entries:
            if not row["claim_label"].strip() and any(row[c].strip() for c in ANNOTATION_FIELDS):
                problems.append(f"{where(number, row)}: fields filled but no claim_label")
        if require_complete and len(labelled) != len(entries):
            problems.append(f"{uid}: a claim row has no claim_label")
        if not labelled:
            if require_complete:
                problems.append(f"{uid}: not annotated")
            continue

        n_claims = len(labelled)
        cause_refs = [r["claim_label"].strip() for _, r in labelled
                      if r["claim_label"].strip() in causes.refs]
        if len(cause_refs) != len(set(cause_refs)):
            problems.append(f"{uid}: a cause ref appears twice in one prediction (V4)")
        for number, row in labelled:
            problems += _validate_claim(
                row, number, n_claims, causes, allowed, architecture, where(number, row)
            )
    return problems


def _validate_claim(
    row: dict, number: int, n_claims: int, causes: CauseSet, allowed: list[str],
    architecture: dict, where: str,
) -> list[str]:
    problems = []
    label = row["claim_label"].strip()
    has = {c: bool(row[c].strip()) for c in ANNOTATION_FIELDS}
    unsure = row["unsure"].strip().lower()
    if label not in allowed:
        return [f"{where}: label {row['claim_label']!r} is not one label of {allowed} (V3)"]
    if unsure not in ("", "yes"):
        problems.append(f"{where}: unsure is {row['unsure']!r}, expected empty or 'yes' (V10)")
    for column in ("target_judgement", "stride_judgement"):
        value = row[column].strip()
        if value not in JUDGEMENT_VALUES:
            problems.append(f"{where}: {column} is {value!r} (V10)")
        elif value and not has["rationale"]:
            problems.append(f"{where}: an override of {column} needs a rationale (V10)")
    if n_claims >= 2 and not (has["claim_text"] and has["rationale"]):
        problems.append(
            f"{where}: with several claims every claim needs claim_text and rationale (V5)"
        )
    if label == VA:
        for column in ("claim_text", "evidence_refs", "candidate_id", "rationale"):
            if not has[column]:
                problems.append(f"{where}: valid_additional needs {column} (V6)")
    for path in split_list(row["evidence_refs"]):
        try:
            resolve_path(architecture, path)
        except (KeyError, StopIteration, ValueError, TypeError):
            problems.append(
                f"{where}: evidence path {path!r} does not exist in the architecture (V7)"
            )
    plausible = split_list(row["plausible_causes"])
    for ref in plausible:
        if ref not in causes.refs:
            problems.append(
                f"{where}: plausible cause {ref!r} is no cause of this architecture (V7)"
            )
    if (label == "pending_review" or unsure == "yes") and not has["rationale"]:
        problems.append(f"{where}: a pending or unsure claim needs a rationale (V8)")
    standard = is_standard_match(row, n_claims, causes)
    if label in causes.refs and not standard and not has["rationale"]:
        problems.append(
            f"{where}: this cause claim is not a standard match and needs a rationale (V9)"
        )
    if plausible:
        if label != "pending_review" and unsure != "yes":
            problems.append(f"{where}: plausible_causes belongs on pending or unsure claims (V11)")
        missing = [ref for ref in plausible if ref not in row["rationale"]]
        if missing:
            problems.append(f"{where}: the rationale must mention {missing} (V11)")
        if not has["evidence_refs"]:
            problems.append(f"{where}: plausible_causes need evidence_refs (V11)")
    code = row["reason_code"].strip()
    if label == UN:
        if code not in REASON_CODES:
            problems.append(
                f"{where}: unsupported needs a reason_code from {list(REASON_CODES)} (V12)"
            )
        if code == "explicit_contradiction" and not has["evidence_refs"]:
            problems.append(f"{where}: explicit_contradiction needs evidence_refs (V12)")
        if code == "other" and not has["rationale"]:
            problems.append(f"{where}: reason_code other needs a rationale (V12)")
    elif code:
        problems.append(f"{where}: reason_code belongs on unsupported claims only (V12)")
    return problems


# --- migration of the first, single-label sheet ------------------------------

LEGACY_LABELS = {
    "none": ("unsupported", False),
    "unsure": ("pending_review", True),
    "new_cause_proposed": ("pending_review", False),
}


def migrate_old_sheet(old_rows: list[dict], template_rows: list[dict]) -> tuple[list[dict], dict]:
    """Move a filled single-label sheet into the claim format, by ``pred_uid``.

    ``label`` becomes ``claim_label`` of claim 1, ``note`` becomes ``rationale``, ``unsure``
    stays. Nothing is invented: an old ``unsupported`` keeps an empty ``reason_code`` and is
    listed so that the owner can fill it. Rows of the old sheet that are not in the new export
    raise an error.
    """
    old = {r["pred_uid"]: r for r in old_rows}
    template_uids = {r["pred_uid"] for r in template_rows}
    unknown = sorted(set(old) - template_uids)
    if unknown:
        raise ax.ExportError(f"{len(unknown)} row(s) of the old sheet are not in the new export")
    migrated, needs_reason, unlabelled = [], [], []
    for content in template_rows:
        row = blank_row(content)
        source = old.get(content["pred_uid"])
        label = (source or {}).get("label", "").strip()
        if not label:
            unlabelled.append(content["pred_uid"])
            migrated.append(row)
            continue
        label, forced_unsure = LEGACY_LABELS.get(label, (label, False))
        row["claim_label"] = label
        row["rationale"] = source["note"]
        row["unsure"] = "yes" if forced_unsure or source["unsure"].strip().lower() == "yes" else ""
        if label == UN:
            needs_reason.append(content["pred_uid"])
        migrated.append(row)
    report = {
        "migrated": len(template_rows) - len(unlabelled), "unlabelled": len(unlabelled),
        "needs_reason_code": needs_reason,
    }
    return migrated, report


# --- the sheet of the repeat annotation ------------------------------------------------------


def repeat_sheet_rows(template_rows: list[dict], selected_uids: list[str]) -> list[dict]:
    """Blank claim rows of the selected predictions, in the order of ``selected_uids``."""
    by_uid = {r["pred_uid"]: r for r in template_rows}
    missing = [u for u in selected_uids if u not in by_uid]
    if missing:
        raise ax.ExportError(f"{len(missing)} selected prediction(s) are not in the export")
    return [blank_row(by_uid[u]) for u in selected_uids]


CLAIM_README = """# Claim annotation sheets (GT {gt_version}, protocol {protocol})

One sheet per architecture. Every prediction has one pre-seeded row (`claim_no` 1). For each
independent, evidenced cause the prediction states, copy the row and give it the next `claim_no`
(rule R9). Do not open `annotation_private/` or any file named `*mapping*`.

Columns to fill in (all after `claim_no`):

- `claim_label`: exactly one of the causes of the architecture (listed per sheet in
  `annotation_claims_meta.json`), `valid_additional`, `unsupported` or `pending_review`.
- `reason_code`: required for `unsupported`: `explicit_contradiction`, `insufficient_evidence`,
  `generic_claim`, `wrong_mechanism`, `out_of_scope` or `other`.
- `claim_text`: the mechanism the claim states (required with several claims).
- `evidence_refs`: architecture paths separated by `;`, for example
  `components.shared_db.config.tenant_isolation`.
- `candidate_id`: a short key that groups the same candidate across predictions
  (`valid_additional`, `pending_review`).
- `plausible_causes`: causes separated by `;` that a pending or unsure claim might be; the
  rationale must name each one and evidence paths must be given.
- `rationale`: the reasoning, with rule numbers. Required except for a standard match (a single
  cause claim, same target, listed category, no doubt) and for a single `unsupported` claim.
- `unsure`: `yes` or empty.
- `target_judgement`, `stride_judgement`: optional `ok` or `deviates`; empty means derived.

All other columns are copied unchanged from the stored prediction. Row order carries no
information.
"""
