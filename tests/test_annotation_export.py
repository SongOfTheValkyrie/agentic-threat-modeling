"""Tests for the blind annotation export (V2_SPEC.md 7.1 and 9).

All data is synthetic and built in temporary directories. The suite mirrors the size of
the real capture: 123 predictions (60 on multi_tenant_saas, 63 on cloud_ingest_pipeline)
from three approaches per architecture.
"""

import csv
import hashlib
import importlib.util
import json
import random
import shutil
import stat
from pathlib import Path

import pytest

from src.evaluation import annotation_export as ax
from src.evaluation.prediction_ids import uids_for_file
from src.evaluation.predictions import read_predictions

ROOT = Path(__file__).resolve().parents[1]
LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
STRIDE = ["spoofing", "tampering", "repudiation", "information_disclosure",
          "denial_of_service", "elevation_of_privilege"]
TARGETS = {
    "multi_tenant_saas": ["api", "shared_db", "document_service", "object_store", "admin_portal"],
    "cloud_ingest_pipeline": ["ingest_api", "raw_bucket", "processing_cluster", "warehouse"],
}
# (architecture, approach) -> number of predictions: 21+22+17 and 21+21+21 = 123.
COUNTS = {
    ("multi_tenant_saas", "rag"): 21,
    ("multi_tenant_saas", "agent_pev"): 22,
    ("multi_tenant_saas", "agent_pev_noplan"): 17,
    ("cloud_ingest_pipeline", "rag"): 21,
    ("cloud_ingest_pipeline", "agent_pev"): 21,
    ("cloud_ingest_pipeline", "agent_pev_noplan"): 21,
}
APPROACHES = ["rag", "agent_pev", "agent_pev_noplan"]


def _script():
    spec = importlib.util.spec_from_file_location(
        "export_annotation_sheet", ROOT / "scripts" / "export_annotation_sheet.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_sources(directory: Path, counts: dict = COUNTS) -> list[Path]:
    """Synthetic prediction files in the stored layout, read-only like the real ones."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for number, ((architecture, approach), count) in enumerate(counts.items()):
        rng = random.Random(number)
        predictions = []
        for i in range(count):
            target = rng.choice(TARGETS[architecture])
            category = rng.choice(STRIDE)
            # Every fifth text is shared by all approaches, to test identical content.
            body = (
                f"Synthetic shared finding {i // 5}" if i % 5 == 0
                else f"Synthetic finding {architecture[:5]} {number}-{i}"
            )
            predictions.append({
                "id": f"{approach}-secret-threat-{i}-{target}",
                "target": target, "target_kind": "component", "category": category,
                "description": body, "mitigation": f"Synthetic mitigation {i % 7}",
                "key": f"{target}:{category}",
            })
        record = {
            "schema_version": 1, "timestamp": f"2026-02-0{number + 1}T10:00:00.000001+00:00",
            "approach": approach, "model": "synthetic-llm:1b", "architecture": architecture,
            "run_index": 0, "code": {"commit": f"{number + 1:040x}", "dirty": False},
            "num_predictions": count, "predictions": predictions,
        }
        path = directory / f"{architecture}_{approach}_synthetic_run0_{number}.json"
        path.write_text(json.dumps(record, indent=1) + "\n")
        path.chmod(0o444)
        paths.append(path)
    return paths


def do_export(tmp_path: Path, paths=None, name="out", seed=ax.SEED):
    sources = paths or make_sources(tmp_path / f"{name}_sources")
    blind = tmp_path / name / "blind"
    mapping = tmp_path / name / "private" / "mapping.json"
    meta = ax.export(sources, blind, mapping, LISTS_DIR, "V2.0", seed=seed)
    return sources, blind, mapping, meta


@pytest.fixture
def exported(tmp_path):
    sources, blind, mapping, meta = do_export(tmp_path)
    return {"sources": sources, "blind": blind, "mapping": mapping, "meta": meta,
            "tmp": tmp_path}


def sheet_rows(blind: Path, architecture: str) -> list[dict]:
    return ax.read_sheet(blind / ax.SHEET_NAME.format(architecture=architecture))


def all_rows(blind: Path) -> list[dict]:
    return [r for a in TARGETS for r in sheet_rows(blind, a)]


# --- completeness --------------------------------------------------------------------------


def test_all_123_stored_predictions_are_exported_exactly_once(exported):
    assert sum(COUNTS.values()) == 123
    problems, stats = ax.verify_export(exported["blind"], exported["mapping"])
    assert problems == []
    assert stats["stored_predictions"] == 123 and stats["exported_rows"] == 123
    assert stats["unique_identifiers"] == 123
    assert stats["rows_per_architecture"] == {"cloud_ingest_pipeline": 63,
                                              "multi_tenant_saas": 60}
    assert exported["meta"]["total_rows"] == 123
    assert len(all_rows(exported["blind"])) == 123


def test_every_stored_prediction_appears_in_the_sheet_of_its_architecture(exported):
    for path in exported["sources"]:
        record = read_predictions(path)
        sheet_uids = {r["pred_uid"] for r in sheet_rows(exported["blind"], record["architecture"])}
        assert set(uids_for_file(path)) <= sheet_uids
    assert len(sheet_rows(exported["blind"], "multi_tenant_saas")) == 60
    assert len(sheet_rows(exported["blind"], "cloud_ingest_pipeline")) == 63


def test_a_dropped_row_is_detected(exported):
    sheet = exported["blind"] / "annotation_multi_tenant_saas.csv"
    rows = ax.read_sheet(sheet)[:-1]
    sheet.chmod(0o644)
    sheet.unlink()
    ax.write_sheet(sheet, rows)
    problems, _ = ax.verify_export(exported["blind"], exported["mapping"])
    assert any("not in the export" in p or "rows" in p for p in problems)


# --- identifiers ---------------------------------------------------------------------------


def test_identifiers_are_unique_and_independent_of_the_model_threat_ids(exported):
    uids = [r["pred_uid"] for r in all_rows(exported["blind"])]
    assert len(uids) == len(set(uids)) == 123
    assert all(u.startswith("pred-") for u in uids)
    # Identical text in different approaches still gets different identifiers.
    shared = [r for r in all_rows(exported["blind"])
              if r["description"] == "Synthetic shared finding 0"]
    assert len(shared) >= 6 and len({r["pred_uid"] for r in shared}) == len(shared)


def test_rewriting_the_threat_ids_of_the_sources_does_not_change_the_identifiers(tmp_path):
    first = make_sources(tmp_path / "a")
    second = make_sources(tmp_path / "b")
    for path in second:
        record = json.loads(path.read_text())
        for i, prediction in enumerate(record["predictions"]):
            prediction["id"] = f"other-{i}"
        path.chmod(0o644)
        path.write_text(json.dumps(record))
    assert [uids_for_file(p) for p in first] == [uids_for_file(p) for p in second]


# --- joining back ----------------------------------------------------------------------------


def test_every_row_joins_back_to_its_original_prediction_run_and_approach(exported):
    mapping = json.loads(exported["mapping"].read_text())
    by_file = {entry["file"]: entry for entry in mapping["sources"]}
    for architecture in TARGETS:
        for position, row in enumerate(sheet_rows(exported["blind"], architecture), start=1):
            link = mapping["predictions"][row["pred_uid"]]
            assert (link["architecture"], link["row_in_sheet"]) == (architecture, position)
            record = read_predictions(link["file"])
            original = record["predictions"][link["index_in_file"]]
            for column in ("target", "target_kind", "category", "description", "mitigation"):
                assert row[column] == original[column]
            assert link["threat_id"] == original["id"]
            assert link["approach"] == record["approach"] == by_file[link["file"]]["approach"]
            assert link["run_index"] == record["run_index"]


def test_the_sheets_of_one_architecture_mix_all_approaches(exported):
    mapping = json.loads(exported["mapping"].read_text())
    for architecture in TARGETS:
        approaches = [mapping["predictions"][r["pred_uid"]]["approach"]
                      for r in sheet_rows(exported["blind"], architecture)]
        assert set(approaches) == set(APPROACHES)
        assert {mapping["predictions"][r["pred_uid"]]["architecture"]
                for r in sheet_rows(exported["blind"], architecture)} == {architecture}
        same_neighbour = sum(a == b for a, b in zip(approaches, approaches[1:], strict=False))
        assert same_neighbour < 0.6 * (len(approaches) - 1), "approaches must not come in blocks"


# --- determinism -----------------------------------------------------------------------------


def test_the_order_is_reproducible_and_independent_of_the_input_order(tmp_path):
    sources = make_sources(tmp_path / "src")
    _, blind_a, mapping_a, _ = do_export(tmp_path, sources, "a")
    _, blind_b, mapping_b, _ = do_export(tmp_path, list(reversed(sources)), "b")
    shuffled = sources[:]
    random.Random(7).shuffle(shuffled)
    _, blind_c, _, _ = do_export(tmp_path, shuffled, "c")
    for architecture in TARGETS:
        name = ax.SHEET_NAME.format(architecture=architecture)
        content = (blind_a / name).read_bytes()
        assert (blind_b / name).read_bytes() == content == (blind_c / name).read_bytes()
    assert json.loads(mapping_a.read_text())["predictions"] == json.loads(
        mapping_b.read_text())["predictions"]
    assert (blind_a / ax.META_NAME).read_text() == (blind_b / ax.META_NAME).read_text()


def test_the_order_follows_the_documented_rule_and_changes_with_the_seed(tmp_path):
    sources = make_sources(tmp_path / "src")
    _, blind_a, _, meta = do_export(tmp_path, sources, "a")
    _, blind_b, _, _ = do_export(tmp_path, sources, "b", seed=1)
    assert meta["seed"] == ax.SEED == 20261103
    assert "sha256" in meta["order_rule"] and "seed" in meta["order_rule"]
    for architecture in TARGETS:
        uids = [r["pred_uid"] for r in sheet_rows(blind_a, architecture)]
        expected = sorted(uids, key=lambda u: hashlib.sha256(f"{ax.SEED}:{u}".encode()).hexdigest())
        assert uids == expected
        other = [r["pred_uid"] for r in sheet_rows(blind_b, architecture)]
        assert other != uids and sorted(other) == sorted(uids)


# --- blindness -------------------------------------------------------------------------------


def test_the_blind_export_holds_no_approach_run_file_or_trace_information(exported):
    blind = exported["blind"]
    mapping = json.loads(exported["mapping"].read_text())
    secrets = set(APPROACHES) | {"synthetic-llm", "run0", "results/", "traces", "secret-threat"}
    for entry in mapping["sources"]:
        secrets |= {entry["timestamp"], Path(entry["file"]).name, entry["code"]["commit"]}
    files = sorted(blind.iterdir())
    assert {f.name for f in files} == {
        ax.META_NAME, ax.README_NAME, "annotation_multi_tenant_saas.csv",
        "annotation_cloud_ingest_pipeline.csv",
    }
    for file in files:
        text = file.read_text()
        for secret in secrets:
            assert secret not in text, f"{file.name} contains {secret!r}"
    for architecture in TARGETS:
        sheet = blind / ax.SHEET_NAME.format(architecture=architecture)
        with sheet.open(newline="", encoding="utf-8") as handle:
            assert csv.DictReader(handle).fieldnames == ax.BLIND_COLUMNS
    assert ax.blindness_problems(blind, mapping) == []


def test_the_meta_file_names_neither_approaches_counts_per_approach_nor_run_data(exported):
    meta = json.loads((exported["blind"] / ax.META_NAME).read_text())
    assert set(meta) == {"schema", "schema_version", "gt_version", "seed", "order_rule", "columns",
                         "total_rows", "sheets", "mapping_sha256"}
    for info in meta["sheets"].values():
        assert set(info) == {"file", "rows", "sha256", "allowed_labels"}


def test_the_private_mapping_must_not_lie_inside_the_blind_export(tmp_path):
    sources = make_sources(tmp_path / "src")
    blind = tmp_path / "blind"
    for mapping in (blind / "mapping.json", blind / "sub" / "m.json"):
        with pytest.raises(ax.ExportError, match="must not lie inside"):
            ax.export(sources, blind, mapping, LISTS_DIR, "V2.0")
    assert not blind.exists() or not any(blind.iterdir())


def test_a_mapping_file_in_the_blind_directory_is_reported(exported):
    (exported["blind"] / "private_mapping.json").write_text("{}")
    mapping = json.loads(exported["mapping"].read_text())
    assert any("mapping file lies" in p for p in ax.blindness_problems(exported["blind"], mapping))


def test_a_leaking_readme_or_meta_is_reported(exported):
    readme = exported["blind"] / ax.README_NAME
    readme.write_text(readme.read_text() + "\nThese rows came from agent_pev.\n")
    mapping = json.loads(exported["mapping"].read_text())
    problems = ax.blindness_problems(exported["blind"], mapping)
    assert any("agent_pev" in p for p in problems)


# --- verbatim texts ---------------------------------------------------------------------------


def test_texts_are_copied_unchanged_including_awkward_characters(tmp_path):
    tricky = [
        'comma, "quotes", and a ; semicolon',
        "line one\nline two\n\nline four",
        "windows\r\nline ending",
        "  leading and trailing spaces  ",
        "unicode: ünïcödé – “quotes” ✓ 日本語",
        "=SUM(A1:A2) and +cmd and @name and -dash",
        "",
        "tab\tseparated",
    ]
    directory = tmp_path / "src"
    sources = make_sources(directory, {("multi_tenant_saas", "rag"): len(tricky)})
    record = json.loads(sources[0].read_text())
    for prediction, text in zip(record["predictions"], tricky, strict=True):
        prediction["description"] = text
        prediction["mitigation"] = text[::-1]
    sources[0].chmod(0o644)
    sources[0].write_text(json.dumps(record))
    sources[0].chmod(0o444)
    _, blind, mapping, _ = do_export(tmp_path, sources)
    rows = sheet_rows(blind, "multi_tenant_saas")
    assert sorted(r["description"] for r in rows) == sorted(tricky)
    assert sorted(r["mitigation"] for r in rows) == sorted(t[::-1] for t in tricky)
    assert ax.verify_export(blind, mapping)[0] == []


# --- the stored predictions stay untouched ------------------------------------------------------


def test_export_and_verification_leave_the_prediction_files_untouched(tmp_path):
    sources = make_sources(tmp_path / "src")
    before = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode) for p in sources}
    listing = sorted(p.name for p in (tmp_path / "src").iterdir())
    _, blind, mapping, _ = do_export(tmp_path, sources)
    ax.verify_export(blind, mapping)
    for path, (digest, mode) in before.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert path.stat().st_mode == mode and not path.stat().st_mode & stat.S_IWUSR
    assert sorted(p.name for p in (tmp_path / "src").iterdir()) == listing


def test_verification_notices_a_prediction_file_that_changed_after_the_export(exported):
    path = exported["sources"][0]
    record = json.loads(path.read_text())
    record["predictions"][0]["description"] += " (edited)"
    path.chmod(0o644)
    path.write_text(json.dumps(record))
    problems, _ = ax.verify_export(exported["blind"], exported["mapping"])
    assert any("source file changed" in p for p in problems)
    # The identifier contains the content, so the edited prediction no longer matches any row.
    assert any("not in the export" in p for p in problems)
    assert any("not a prediction of any source file" in p for p in problems)


def test_export_never_overwrites_existing_files(tmp_path):
    sources, blind, mapping, _ = do_export(tmp_path)
    snapshot = {p: p.read_bytes() for p in [mapping, *blind.iterdir()]}
    with pytest.raises(ax.ExportError, match="refusing to overwrite"):
        ax.export(sources, blind, mapping, LISTS_DIR, "V2.0")
    assert {p: p.read_bytes() for p in snapshot} == snapshot


def test_two_files_for_the_same_run_or_the_same_file_twice_are_rejected(tmp_path):
    sources = make_sources(tmp_path / "src")
    with pytest.raises(ax.ExportError, match="same file"):
        ax.load_sources([sources[0], sources[0]])
    copy = tmp_path / "src" / "copy.json"
    shutil.copy(sources[0], copy)
    with pytest.raises(ax.ExportError, match="same architecture, approach"):
        ax.load_sources([sources[0], copy])


# --- verification catches tampering -----------------------------------------------------------


def _rewrite(sheet: Path, rows: list[dict]) -> None:
    sheet.unlink()
    ax.write_sheet(sheet, rows)


def test_verification_catches_changed_text_swapped_rows_and_filled_labels(exported):
    sheet = exported["blind"] / "annotation_cloud_ingest_pipeline.csv"
    rows = ax.read_sheet(sheet)

    changed = [dict(r) for r in rows]
    changed[3]["description"] += "!"
    _rewrite(sheet, changed)
    assert any("description differs" in p for p in ax.verify_export(
        exported["blind"], exported["mapping"])[0])

    swapped = [dict(r) for r in rows]
    swapped[0], swapped[1] = swapped[1], swapped[0]
    _rewrite(sheet, swapped)
    assert any("order does not follow" in p for p in ax.verify_export(
        exported["blind"], exported["mapping"])[0])

    labelled = [dict(r) for r in rows]
    labelled[0]["label"] = "CIP-01"
    _rewrite(sheet, labelled)
    assert any("annotation column is filled" in p for p in ax.verify_export(
        exported["blind"], exported["mapping"])[0])


def test_verification_catches_a_changed_mapping(exported):
    mapping = json.loads(exported["mapping"].read_text())
    first = next(iter(mapping["predictions"]))
    mapping["predictions"][first]["index_in_file"] += 1
    exported["mapping"].write_text(json.dumps(mapping))
    problems, _ = ax.verify_export(exported["blind"], exported["mapping"])
    assert any("mapping checksum differs" in p for p in problems)


# --- no labels are assigned -------------------------------------------------------------------


def test_a_fresh_export_carries_no_label_unsure_flag_or_note(exported):
    rows = all_rows(exported["blind"])
    assert all(r["label"] == "" and r["unsure"] == "" and r["note"] == "" for r in rows)


# --- annotation sheet rules ---------------------------------------------------------------------


def test_allowed_labels_are_the_causes_of_the_architecture_plus_three_fixed_labels():
    mts = ax.allowed_labels("multi_tenant_saas", LISTS_DIR)
    cip = ax.allowed_labels("cloud_ingest_pipeline", LISTS_DIR)
    assert mts == [f"MTS-0{i}" for i in range(1, 7)] + ["valid_additional", "unsupported",
                                                        "pending_review"]
    assert cip[:11] == [f"CIP-{i:02d}" for i in range(1, 12)] and len(cip) == 14
    for excluded in ("MTS-X1", "MTS-B1", "MTS-U1", "none", "unsure", "new_cause_proposed"):
        assert excluded not in mts


def test_exactly_one_allowed_label_per_row_is_enforced(exported):
    rows = sheet_rows(exported["blind"], "multi_tenant_saas")
    allowed = ax.allowed_labels("multi_tenant_saas", LISTS_DIR)
    good = [dict(r, label="MTS-01") for r in rows]
    good[1]["label"] = "valid_additional"
    good[2]["unsure"] = "yes"
    assert ax.check_annotations(good, allowed, require_complete=True) == []

    for bad_label in ("MTS-01;MTS-02", "MTS-01, MTS-02", "MTS-X1", "CIP-01", "none", "mts-01",
                      "MTS-07", "valid additional"):
        bad = [dict(r, label="MTS-01") for r in rows]
        bad[0]["label"] = bad_label
        problems = ax.check_annotations(bad, allowed, require_complete=True)
        assert len(problems) == 1 and "not one label" in problems[0], bad_label


def test_incomplete_duplicate_and_bad_unsure_values_are_reported(exported):
    rows = sheet_rows(exported["blind"], "multi_tenant_saas")
    allowed = ax.allowed_labels("multi_tenant_saas", LISTS_DIR)
    partial = [dict(r) for r in rows]
    partial[0]["label"] = "MTS-02"
    assert ax.check_annotations(partial, allowed, require_complete=False) == []
    assert len(ax.check_annotations(partial, allowed, require_complete=True)) == len(rows) - 1

    duplicated = [dict(r, label="MTS-01") for r in rows] + [dict(rows[0], label="MTS-01")]
    assert any("appears twice" in p for p in ax.check_annotations(duplicated, allowed, True))

    odd = [dict(r, label="MTS-01") for r in rows]
    odd[0]["unsure"] = "maybe"
    assert any("unsure" in p for p in ax.check_annotations(odd, allowed, True))


def test_labels_keyed_by_identifier_feed_the_cause_recall_functions(exported):
    """Join sheet labels to a stored file and compute both recalls (end to end)."""
    spec = importlib.util.spec_from_file_location(
        "check_cause_consistency", ROOT / "scripts" / "check_cause_consistency.py"
    )
    cc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cc)

    rows = sheet_rows(exported["blind"], "multi_tenant_saas")
    mapping = json.loads(exported["mapping"].read_text())
    pev_file = next(e["file"] for e in mapping["sources"]
                    if e["architecture"] == "multi_tenant_saas" and e["approach"] == "agent_pev")
    pev_uids = set(uids_for_file(pev_file))
    labelled = []
    for i, row in enumerate(rows):
        label = ("MTS-02", "MTS-05", "unsupported", "valid_additional", "pending_review")[i % 5]
        labelled.append(dict(row, label=label, unsure="yes" if i % 7 == 0 else ""))
    assert ax.check_annotations(labelled, ax.allowed_labels("multi_tenant_saas", LISTS_DIR),
                                True) == []

    by_uid = ax.labels_by_uid(labelled)
    own = {uid: label for uid, label in by_uid.items() if uid in pev_uids}
    labels = cc.labels_in_file_order(pev_file, own)
    draft = cc.load_drafts()["multi_tenant_saas"]
    result = cc.score_prediction_file(pev_file, labels, draft)
    assert result["found"] == sorted({"MTS-02", "MTS-05"} & set(labels))
    claims = cc.cause_claim_counts(draft, labels)
    assert claims["valid_additional"] == labels.count("valid_additional")
    assert claims["unsupported"] == labels.count("unsupported")
    assert claims["pending_review"] == labels.count("pending_review")
    assert ax.unsure_uids(labelled) == {r["pred_uid"] for r in labelled if r["unsure"] == "yes"}


# --- command line and the synthetic example ---------------------------------------------------


def test_the_synthetic_example_command_writes_a_verifiable_export(tmp_path):
    script = _script()

    class Args:
        out = str(tmp_path / "example")

    assert script.cmd_example(Args) == 0
    blind = Path(Args.out) / "blind"
    mapping = Path(Args.out) / "private_mapping_of_the_example.json"
    # Paths in the mapping are absolute here (tmp_path), so the check can resolve them.
    problems, stats = ax.verify_export(blind, mapping)
    assert problems == [] and stats["stored_predictions"] == 14
    assert not (blind / mapping.name).exists()
