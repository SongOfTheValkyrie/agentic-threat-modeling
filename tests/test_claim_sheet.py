"""The claim-level annotation sheet: export, verification, validation V1 to V12, migration.

Synthetic data only. The export tests reuse the 123-prediction layout of
``test_annotation_export``.
"""

import json
import shutil
from pathlib import Path

import pytest
import test_annotation_export as te

from src.evaluation import annotation_export as ax
from src.evaluation import claim_sheet as cs

ROOT = Path(__file__).resolve().parents[1]
LISTS = ROOT / "benchmark_v2" / "v2.0"
ARCH_FILE = ROOT / "benchmark" / "multi_tenant_saas.json"
MTS = cs.cause_set("multi_tenant_saas", LISTS)
CIP = cs.cause_set("cloud_ingest_pipeline", LISTS)


@pytest.fixture
def first_export(tmp_path):
    sources, blind, mapping, meta = te.do_export(tmp_path)
    return {"tmp": tmp_path, "sources": sources, "blind": blind, "mapping": mapping, "meta": meta}


@pytest.fixture
def claim_export(first_export):
    directory = first_export["tmp"] / "claims"
    meta = cs.export_claim_sheets(directory, first_export["mapping"], LISTS, "V2.0")
    return {**first_export, "claims": directory, "claim_meta": meta}


# --- export ------------------------------------------------------------------------------


def test_the_claim_export_covers_all_123_predictions_in_the_order_of_the_first_export(claim_export):
    problems, stats = cs.verify_claim_export(claim_export["claims"], claim_export["mapping"])
    assert problems == []
    assert stats["stored_predictions"] == stats["claim_rows"] == stats["unique_identifiers"] == 123
    assert stats["predictions_per_architecture"] == {"cloud_ingest_pipeline": 63,
                                                     "multi_tenant_saas": 60}
    for architecture in te.TARGETS:
        old = [r["pred_uid"] for r in te.sheet_rows(claim_export["blind"], architecture)]
        new = [r["pred_uid"] for r in cs.read_claim_sheet(
            claim_export["claims"] / cs.CLAIM_SHEET_NAME.format(architecture=architecture))]
        assert new == old


def test_the_private_mapping_is_only_read_and_stays_valid(claim_export):
    before = ax.file_sha256(claim_export["mapping"])
    assert claim_export["claim_meta"]["mapping_sha256"] == before
    assert ax.verify_export(claim_export["blind"], claim_export["mapping"])[0] == []
    assert ax.file_sha256(claim_export["mapping"]) == before


def test_a_fresh_claim_export_holds_one_empty_claim_row_per_prediction(claim_export):
    for architecture in te.TARGETS:
        rows = cs.read_claim_sheet(
            claim_export["claims"] / cs.CLAIM_SHEET_NAME.format(architecture=architecture))
        assert all(r["claim_no"] == "1" for r in rows)
        assert all(not r[c] for r in rows for c in cs.ANNOTATION_FIELDS)


def test_the_claim_export_holds_no_approach_run_file_or_trace_information(claim_export):
    mapping = json.loads(claim_export["mapping"].read_text())
    secrets = set(te.APPROACHES) | {"synthetic-llm", "run0", "results/", "secret-threat"}
    for entry in mapping["sources"]:
        secrets |= {entry["timestamp"], Path(entry["file"]).name, entry["code"]["commit"]}
    files = sorted(claim_export["claims"].iterdir())
    assert {f.name for f in files} == {
        cs.CLAIM_META_NAME, cs.CLAIM_README_NAME, "annotation_claims_multi_tenant_saas.csv",
        "annotation_claims_cloud_ingest_pipeline.csv",
    }
    for file in files:
        text = file.read_text()
        for secret in secrets:
            assert secret not in text, f"{file.name} contains {secret!r}"
    assert cs.claim_blindness_problems(claim_export["claims"], mapping) == []
    meta = json.loads((claim_export["claims"] / cs.CLAIM_META_NAME).read_text())
    assert meta["protocol_version"] == "1.1" and meta["columns"] == cs.CLAIM_COLUMNS
    assert meta["reason_codes"] == list(cs.REASON_CODES)


def test_the_claim_export_never_overwrites_and_refuses_a_mapping_inside_it(claim_export):
    with pytest.raises(ax.ExportError, match="refusing to overwrite"):
        cs.export_claim_sheets(claim_export["claims"], claim_export["mapping"], LISTS, "V2.0")
    with pytest.raises(ax.ExportError, match="must not lie inside"):
        inside = claim_export["claims"] / "mapping.json"
        shutil.copy(claim_export["mapping"], inside)
        cs.export_claim_sheets(claim_export["claims"], inside, LISTS, "V2.0")


def test_a_changed_prediction_file_stops_the_export(first_export):
    path = first_export["sources"][0]
    record = json.loads(path.read_text())
    record["predictions"][0]["description"] += "!"
    path.chmod(0o644)
    path.write_text(json.dumps(record))
    with pytest.raises(ax.ExportError, match="changed since the first export"):
        cs.export_claim_sheets(first_export["tmp"] / "x", first_export["mapping"], LISTS, "V2.0")


def test_verification_catches_a_filled_row_a_changed_text_and_a_dropped_row(claim_export):
    sheet = claim_export["claims"] / "annotation_claims_multi_tenant_saas.csv"
    rows = cs.read_claim_sheet(sheet)
    for mutate, expected in (
        (lambda r: r[0].update(claim_label="MTS-01"), "one empty claim row"),
        (lambda r: r[1].update(description=r[1]["description"] + "!"), "description differs"),
        (lambda r: r.pop(), "missing"),
    ):
        changed = [dict(r) for r in rows]
        mutate(changed)
        sheet.chmod(0o644)
        sheet.unlink()
        cs.write_claim_sheet(sheet, changed)
        problems, _ = cs.verify_claim_export(claim_export["claims"], claim_export["mapping"])
        assert any(expected in p for p in problems), (expected, problems)


# --- validation V1 to V12 ----------------------------------------------------------------


def template():
    """Three synthetic predictions on multi_tenant_saas."""
    content = [
        {"pred_uid": "pred-t1", "architecture": "multi_tenant_saas", "target": "shared_db",
         "target_kind": "component", "category": "information_disclosure",
         "description": "d1", "mitigation": "m1"},
        {"pred_uid": "pred-t2", "architecture": "multi_tenant_saas", "target": "api",
         "target_kind": "component", "category": "spoofing", "description": "d2",
         "mitigation": "m2"},
        {"pred_uid": "pred-t3", "architecture": "multi_tenant_saas", "target": "object_store",
         "target_kind": "component", "category": "tampering", "description": "d3",
         "mitigation": "m3"},
    ]
    return [cs.blank_row(c) for c in content]


def filled(overrides: dict[str, list[dict]]) -> list[dict]:
    """Template rows with the given claim rows per uid (each a dict of fields to set)."""
    rows = []
    for base in template():
        specs = overrides.get(base["pred_uid"], [{}])
        for number, spec in enumerate(specs, start=1):
            row = dict(base)
            row["claim_no"] = str(number)
            row.update(spec)
            rows.append(row)
    return rows


def check(rows, require_complete=False, causes=MTS):
    return cs.validate_claim_rows(rows, template(), causes, ARCH_FILE, require_complete)


def has(problems, tag):
    return any(tag in p for p in problems)


def test_a_standard_match_needs_no_reasoning_and_an_unlabelled_sheet_is_accepted():
    assert check(filled({})) == []
    rows = filled({"pred-t1": [{"claim_label": "MTS-04"}]})
    assert check(rows) == []
    assert cs.is_standard_match(rows[0], 1, MTS)


def test_a_complete_sheet_needs_a_label_on_every_prediction():
    problems = check(filled({"pred-t1": [{"claim_label": "MTS-04"}]}), require_complete=True)
    assert has(problems, "pred-t2: not annotated") and has(problems, "pred-t3: not annotated")


def test_v9_a_cause_claim_that_is_not_a_standard_match_needs_a_rationale():
    deviating = filled({"pred-t2": [{"claim_label": "MTS-01"}]})  # api spoofing: category deviates
    assert has(check(deviating), "(V9)")
    deviating[1]["rationale"] = "R1: the cause is right, the category differs"
    assert check(deviating) == []
    # object_store versus document_service: the target deviates
    wrong_target = filled({"pred-t3": [{"claim_label": "MTS-03"}]})
    assert has(check(wrong_target), "(V9)")
    unsure = filled({"pred-t1": [{"claim_label": "MTS-04", "unsure": "yes"}]})
    assert has(check(unsure), "(V8)")


def test_v3_one_allowed_label_only():
    for bad in ("MTS-01;MTS-02", "MTS-01, MTS-02", "MTS-X1", "CIP-01", "none", "mts-01", "MTS-07"):
        assert has(check(filled({"pred-t1": [{"claim_label": bad}]})), "(V3)"), bad


def test_v1_claim_numbers_and_missing_predictions():
    gap = filled({"pred-t1": [{"claim_label": "MTS-04"}, {"claim_label": "unsupported"}]})
    gap[1]["claim_no"] = "3"
    assert has(check(gap), "(V1)")
    assert has(check(filled({})[:-1]), "pred-t3: no claim row (V1)")
    assert has(check(filled({}) + [dict(filled({})[0], pred_uid="pred-zz")]), "not a prediction")


def test_v2_the_stored_content_cannot_be_edited():
    rows = filled({"pred-t1": [{"claim_label": "MTS-04"}]})
    rows[0]["description"] = "edited"
    assert has(check(rows), "description differs from the export (V2)")


def test_v4_and_v5_several_claims():
    two = filled({"pred-t1": [
        {"claim_label": "MTS-04", "claim_text": "no isolation", "rationale": "R9"},
        {"claim_label": "MTS-04", "claim_text": "again", "rationale": "R9"}]})
    assert has(check(two), "(V4)")
    thin = filled({"pred-t1": [{"claim_label": "MTS-04"},
                               {"claim_label": "MTS-01", "claim_text": "t", "rationale": "r"}]})
    assert has(check(thin), "(V5)")
    good = filled({"pred-t1": [
        {"claim_label": "MTS-04", "claim_text": "no isolation", "rationale": "R9"},
        {"claim_label": "MTS-01", "claim_text": "tenant from request", "rationale": "R9"}]})
    assert check(good) == []


def test_v6_and_v7_valid_additional_and_evidence_paths():
    bare = filled({"pred-t1": [{"claim_label": "valid_additional"}]})
    problems = check(bare)
    for field in ("claim_text", "evidence_refs", "candidate_id", "rationale"):
        assert has(problems, f"needs {field} (V6)")
    good = filled({"pred-t1": [{
        "claim_label": "valid_additional", "claim_text": "t", "candidate_id": "k",
        "rationale": "R12", "evidence_refs": "components.api.config.authentication"}]})
    assert check(good) == []
    good[0]["evidence_refs"] = "components.api.config.nonexistent"
    assert has(check(good), "(V7)")
    good[0]["evidence_refs"] = "components.ghost.config.x"
    assert has(check(good), "(V7)")


def test_v8_pending_and_unsure_claims_need_a_rationale():
    assert has(check(filled({"pred-t1": [{"claim_label": "pending_review"}]})), "(V8)")
    ok = filled({"pred-t1": [{"claim_label": "pending_review", "rationale": "undecided"}]})
    assert check(ok) == []


def test_v10_judgements():
    row = {"claim_label": "MTS-04", "target_judgement": "bad"}
    assert has(check(filled({"pred-t1": [row]})), "(V10)")
    row = {"claim_label": "MTS-04", "stride_judgement": "deviates"}
    assert has(check(filled({"pred-t1": [row]})), "needs a rationale (V10)")
    row = {"claim_label": "MTS-04", "stride_judgement": "deviates", "rationale": "owner view"}
    assert check(filled({"pred-t1": [row]})) == []
    assert has(check(filled({"pred-t1": [{"claim_label": "MTS-04", "unsure": "maybe",
                                           "rationale": "x"}]})), "unsure")


def test_v11_plausible_causes_must_be_justified():
    base = {"claim_label": "pending_review", "plausible_causes": "MTS-03;MTS-05",
            "evidence_refs": "components.document_service.config.object_ownership_check",
            "rationale": "MTS-03 is the ownership check, MTS-05 the prefix"}
    assert check(filled({"pred-t3": [base]})) == []
    no_refs = filled({"pred-t3": [dict(base, rationale="ownership check")]})
    assert has(check(no_refs), "must mention")
    assert has(check(filled({"pred-t3": [dict(base, evidence_refs="")]})), "need evidence_refs")
    assert has(check(filled({"pred-t3": [dict(base, plausible_causes="CIP-01")]})), "(V7)")
    on_unsupported = {"claim_label": "unsupported", "reason_code": "generic_claim",
                      "plausible_causes": "MTS-03", "rationale": "MTS-03",
                      "evidence_refs": "components.api.config.authentication"}
    assert has(check(filled({"pred-t3": [on_unsupported]})), "belongs on pending or unsure")


def test_v12_every_unsupported_claim_has_a_standard_reason_code():
    assert has(check(filled({"pred-t1": [{"claim_label": "unsupported"}]})), "(V12)")
    assert has(check(filled({"pred-t1": [{"claim_label": "unsupported", "reason_code": "x"}]})),
               "(V12)")
    for code in ("insufficient_evidence", "generic_claim", "wrong_mechanism", "out_of_scope"):
        row = {"claim_label": "unsupported", "reason_code": code}
        assert check(filled({"pred-t1": [row]})) == []
    contradiction = {"claim_label": "unsupported", "reason_code": "explicit_contradiction"}
    assert has(check(filled({"pred-t1": [contradiction]})), "needs evidence_refs (V12)")
    ok = dict(contradiction, evidence_refs="components.object_store.config.public_access")
    assert check(filled({"pred-t1": [ok]})) == []
    assert has(check(filled({"pred-t1": [{"claim_label": "unsupported", "reason_code": "other"}]})),
               "needs a rationale (V12)")
    cause_with_code = {"claim_label": "MTS-04", "reason_code": "generic_claim"}
    assert has(check(filled({"pred-t1": [cause_with_code]})), "only")


def test_a_single_unsupported_claim_needs_a_reason_code_but_no_rationale():
    rows = filled({"pred-t1": [{"claim_label": "unsupported", "reason_code": "generic_claim"}]})
    assert check(rows) == []


def test_fields_without_a_label_are_reported():
    orphan = filled({"pred-t1": [{"rationale": "orphan"}]})
    assert has(check(orphan), "fields filled but no claim_label")


# --- rows to claims ----------------------------------------------------------------------


def test_rows_become_claims_for_the_scorer():
    rows = filled({"pred-t1": [{"claim_label": "MTS-04"}],
                   "pred-t3": [{"claim_label": "pending_review", "unsure": "yes",
                                "plausible_causes": "MTS-03; MTS-05", "rationale": "MTS-03 MTS-05",
                                "evidence_refs": "components.api.config.authentication; a.b"}]})
    claims = cs.rows_to_claims(rows)
    assert [(c.pred_uid, c.label) for c in claims] == [("pred-t1", "MTS-04"),
                                                       ("pred-t3", "pending_review")]
    assert claims[1].unsure and claims[1].plausible_causes == ("MTS-03", "MTS-05")
    assert claims[1].evidence_refs == ("components.api.config.authentication", "a.b")


# --- migration ---------------------------------------------------------------------------


def old_rows(labels: dict[str, tuple[str, str, str]]) -> list[dict]:
    rows = []
    for t in template():
        label, unsure, note = labels.get(t["pred_uid"], ("", "", ""))
        rows.append({**{c: t[c] for c in ax.CONTENT_COLUMNS},
                     "label": label, "unsure": unsure, "note": note})
    return rows


def test_migration_moves_label_note_and_unsure_and_invents_nothing():
    old = old_rows({"pred-t1": ("MTS-04", "", "R1 fine"),
                    "pred-t2": ("unsupported", "", "too generic"),
                    "pred-t3": ("pending_review", "yes", "undecided")})
    migrated, report = cs.migrate_old_sheet(old, template())
    by_uid = {r["pred_uid"]: r for r in migrated}
    one, two = by_uid["pred-t1"], by_uid["pred-t2"]
    assert (one["claim_label"], one["rationale"]) == ("MTS-04", "R1 fine")
    assert (two["claim_label"], two["reason_code"]) == ("unsupported", "")
    assert by_uid["pred-t3"]["unsure"] == "yes"
    assert report == {"migrated": 3, "unlabelled": 0, "needs_reason_code": ["pred-t2"]}
    # The only gap is the reason code, and the validator lists exactly that.
    problems = check(migrated)
    assert len(problems) == 1 and has(problems, "(V12)")


def test_migration_keeps_the_order_of_the_new_export_and_maps_legacy_names():
    old = old_rows({"pred-t1": ("none", "", ""), "pred-t2": ("unsure", "", "n"),
                    "pred-t3": ("new_cause_proposed", "", "n")})
    migrated, report = cs.migrate_old_sheet(list(reversed(old)), template())
    assert [r["pred_uid"] for r in migrated] == ["pred-t1", "pred-t2", "pred-t3"]
    labels = [(r["claim_label"], r["unsure"]) for r in migrated]
    assert labels == [("unsupported", ""), ("pending_review", "yes"), ("pending_review", "")]
    assert report["needs_reason_code"] == ["pred-t1"]


def test_migration_leaves_unlabelled_rows_blank_and_rejects_unknown_rows():
    migrated, report = cs.migrate_old_sheet(old_rows({}), template())
    assert report["unlabelled"] == 3 and all(not r["claim_label"] for r in migrated)
    bad = old_rows({}) + [dict(old_rows({})[0], pred_uid="pred-zz")]
    with pytest.raises(ax.ExportError, match="not in the new export"):
        cs.migrate_old_sheet(bad, template())


def test_the_real_first_sheet_migrates_without_loss_of_rows(claim_export):
    for architecture in te.TARGETS:
        old = te.sheet_rows(claim_export["blind"], architecture)
        new_template = cs.read_claim_sheet(
            claim_export["claims"] / cs.CLAIM_SHEET_NAME.format(architecture=architecture))
        old[0]["label"] = "unsupported"
        migrated, report = cs.migrate_old_sheet(old, new_template)
        assert len(migrated) == len(old) and report["needs_reason_code"] == [old[0]["pred_uid"]]


# --- the sheet of the repeat annotation --------------------------------------------------


def test_the_repeat_sheet_is_blank_in_the_given_order():
    rows = cs.repeat_sheet_rows(template(), ["pred-t3", "pred-t1"])
    assert [r["pred_uid"] for r in rows] == ["pred-t3", "pred-t1"]
    assert all(not r[c] for r in rows for c in cs.ANNOTATION_FIELDS)
    with pytest.raises(ax.ExportError):
        cs.repeat_sheet_rows(template(), ["pred-zz"])


# --- the committed claim sheets ----------------------------------------------------------


def test_the_committed_claim_sheets_are_unlabelled_and_match_the_first_export():
    first = ROOT / "benchmark_v2" / "annotation" / "blind"
    claims = ROOT / "benchmark_v2" / "annotation" / "blind_claims"
    if not claims.exists():
        pytest.skip("claim sheets not generated")
    for architecture in te.TARGETS:
        old = ax.read_sheet(first / ax.SHEET_NAME.format(architecture=architecture))
        new = cs.read_claim_sheet(claims / cs.CLAIM_SHEET_NAME.format(architecture=architecture))
        assert [r["pred_uid"] for r in new] == [r["pred_uid"] for r in old]
        for o, n in zip(old, new, strict=True):
            assert all(o[c] == n[c] for c in ax.CONTENT_COLUMNS)
        assert all(not r[c] for r in new for c in cs.ANNOTATION_FIELDS)
        assert cs.validate_claim_rows(new, new, cs.cause_set(architecture, LISTS),
                                      ROOT / "benchmark" / f"{architecture}.json") == []
