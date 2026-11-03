"""The frozen V2.0 cause lists must match their recorded checksums."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "freeze_cause_lists", ROOT / "scripts" / "freeze_cause_lists.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fz = _load_script()


def test_the_manifest_matches_the_files_on_disk():
    assert fz.verify() == []


def test_the_manifest_records_both_lists_denominators_and_checksums():
    manifest = json.loads(fz.MANIFEST.read_text())
    assert manifest["gt_version"] == "V2.0"
    assert manifest["frozen_on"] == "2026-11-03"
    lists = manifest["cause_lists"]
    assert set(lists) == {"multi_tenant_saas.causes.json", "cloud_ingest_pipeline.causes.json"}
    assert sum(v["threat_cause_recall_denominator"] for v in lists.values()) == 15
    assert sum(v["security_control_gap_recall_denominator"] for v in lists.values()) == 17
    for entry in lists.values():
        assert len(entry["sha256"]) == len(entry["architecture_sha256"]) == 64


def test_architecture_checksums_agree_with_the_prefix_stored_in_each_list():
    manifest = json.loads(fz.MANIFEST.read_text())
    for name, entry in manifest["cause_lists"].items():
        stored = json.loads((fz.LISTS_DIR / name).read_text())["provenance"]["derived_from"]
        assert entry["architecture_sha256"].startswith(stored["sha256_16"]), name


@pytest.fixture
def copy_of_the_frozen_tree(tmp_path):
    directory = tmp_path / "benchmark_v2" / "v2.0"
    shutil.copytree(fz.LISTS_DIR, directory)
    (tmp_path / "benchmark").mkdir()
    for name in ("multi_tenant_saas", "cloud_ingest_pipeline"):
        shutil.copy(ROOT / "benchmark" / f"{name}.json", tmp_path / "benchmark")
    return tmp_path


def _verify(tmp_path: Path) -> list[str]:
    return fz.verify(tmp_path / "benchmark_v2" / "v2.0", tmp_path,
                     tmp_path / "benchmark_v2" / "v2.0" / "MANIFEST.json")


def test_the_unmodified_copy_verifies(copy_of_the_frozen_tree):
    assert _verify(copy_of_the_frozen_tree) == []


def test_editing_a_frozen_list_is_detected(copy_of_the_frozen_tree):
    path = copy_of_the_frozen_tree / "benchmark_v2" / "v2.0" / "cloud_ingest_pipeline.causes.json"
    path.write_text(path.read_text().replace("IMDSv2", "IMDSv3", 1))
    problems = _verify(copy_of_the_frozen_tree)
    assert any("cloud_ingest_pipeline.causes.json: sha256 changed" in p for p in problems)


def test_changing_an_architecture_file_is_detected(copy_of_the_frozen_tree):
    path = copy_of_the_frozen_tree / "benchmark" / "multi_tenant_saas.json"
    path.write_text(path.read_text() + "\n")
    problems = _verify(copy_of_the_frozen_tree)
    assert any("multi_tenant_saas.causes.json: architecture_sha256 changed" in p
               for p in problems)


def test_a_removed_list_is_detected(copy_of_the_frozen_tree):
    (copy_of_the_frozen_tree / "benchmark_v2" / "v2.0" / "multi_tenant_saas.causes.json").unlink()
    assert any("present on one side only" in p for p in _verify(copy_of_the_frozen_tree))


def test_write_refuses_to_refreeze(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["freeze_cause_lists.py", "--write"])
    assert fz.main() == 1
    assert "not re-frozen" in capsys.readouterr().out
