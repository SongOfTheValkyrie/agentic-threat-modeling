"""Consistency of the annotation protocol 1.0 and its development cases."""

import json
import re
from pathlib import Path

from src.evaluation import annotation_export as ax

ROOT = Path(__file__).resolve().parents[1]
ANNOTATION = ROOT / "benchmark_v2" / "annotation"
LISTS_DIR = ROOT / "benchmark_v2" / "v2.0"
PROTOCOL = (ANNOTATION / "PROTOCOL.md").read_text()
DEV = json.loads((ANNOTATION / "dev_cases_protocol_v1.json").read_text())


def test_the_protocol_is_versioned_and_holds_all_twelve_rules():
    assert re.search(r"^\*\*Version 1\.1\*\*", PROTOCOL, re.MULTILINE)
    assert DEV["protocol_version"] == "1.0", "the development cases were decided under 1.0"
    for number in range(1, 13):
        assert f"**R{number}," in PROTOCOL, f"R{number} is missing"
    assert "## 8. Change log" in PROTOCOL and "- 1.0 (" in PROTOCOL and "- 1.1 (" in PROTOCOL


def test_the_twelve_development_cases_exist_in_the_blind_sheet_unchanged():
    cases = DEV["cases"]
    assert [c["no"] for c in cases] == list(range(1, 13))
    uids = [c["pred_uid"] for c in cases]
    assert len(set(uids)) == 12
    sheet = {r["pred_uid"]: r for r in ax.read_sheet(
        ANNOTATION / "blind" / "annotation_multi_tenant_saas.csv")}
    for case in cases:
        row = sheet[case["pred_uid"]]
        assert (row["target"], row["category"]) == (case["target"], case["category"])


def test_decisions_are_allowed_labels_and_the_two_reservations_are_marked():
    allowed = ax.allowed_labels("multi_tenant_saas", LISTS_DIR)
    for case in DEV["cases"]:
        assert case["decision"] in allowed, case["no"]
    by_no = {c["no"]: c for c in DEV["cases"]}
    open_cases = {no: c for no, c in by_no.items() if c["status"] != "decided"}
    assert set(open_cases) == {10}, "only case 10 is still open"
    ten = by_no[10]
    assert (ten["decision"], ten["status"]) == ("pending_review", "open")
    assert ten["reservation"].strip()
    eight = by_no[8]
    assert (eight["decision"], eight["status"]) == ("unsupported", "decided")
    assert eight["note"].strip()


def test_the_development_cases_are_not_a_validation_sample():
    assert DEV["excluded_from_validation"] is True
    assert "must not be used as an independent validation sample" in PROTOCOL


def test_the_protocol_table_agrees_with_the_json_record():
    rows = re.findall(r"^\| (\d+) \| `(pred-[0-9a-f]{16})` \| \S+ \| \S+ \| (\S+) \|", PROTOCOL,
                      re.MULTILINE)
    assert len(rows) == 12
    by_no = {c["no"]: c for c in DEV["cases"]}
    for no, uid, decision in rows:
        assert by_no[int(no)]["pred_uid"] == uid
        assert by_no[int(no)]["decision"] == decision
