"""Offline tests for scripts/ollama_smoke_test.py.

The smoke script itself needs a running Ollama. These tests cover everything
that does not: the isolation proof, the preflight logic, the environment it
builds for ``main``, and the output checks (against a sandbox produced by the
real ``main.run_benchmark`` with the stub LLM). Nothing here contacts Ollama
except one call to an address where nothing listens.
"""

import importlib.util
import inspect
import json
import os
import shutil
import stat
from pathlib import Path

import golden_support as gs
import pytest

import main
from src.agent.structured import StructuredAgentThreatModeler
from src.deterministic.modeler import DeterministicThreatModeler
from src.models.loader import load_architecture
from src.RAG.knowledge import load_knowledge_base
from src.RAG.llm import OllamaClient
from src.RAG.retriever import KeywordRetriever

ROOT = Path(__file__).resolve().parents[1]
ARCH = "simple_web_api"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "ollama_smoke_test", ROOT / "scripts" / "ollama_smoke_test.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load_script()


# --- consistency with the code base -------------------------------------------


def test_default_host_and_model_equal_the_ollama_client_defaults():
    defaults = inspect.signature(OllamaClient.__init__).parameters
    assert smoke.DEFAULT_HOST == defaults["host"].default
    assert smoke.DEFAULT_MODEL == defaults["model"].default


def test_every_approach_switch_is_one_main_reads():
    source = (ROOT / "main.py").read_text()
    for variable in smoke.APPROACH_ENV.values():
        assert f'os.environ.get("{variable}")' in source, variable


def test_controlled_env_covers_every_switch_main_reads():
    source = (ROOT / "main.py").read_text()
    import re

    read = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', source))
    assert read <= set(smoke.CONTROLLED_ENV), read - set(smoke.CONTROLLED_ENV)


# --- isolation proof -------------------------------------------------------------


def _make_tree(root: Path) -> None:
    (root / "results" / "predictions").mkdir(parents=True)
    (root / "frozen" / "v1").mkdir(parents=True)
    (root / "results" / "results.jsonl").write_text("a\n")
    (root / "results" / "predictions" / "p.json").write_text("{}")
    (root / "frozen" / "v1" / "MANIFEST.md").write_text("m")


def test_snapshot_is_stable_and_diff_is_empty_without_changes(tmp_path):
    _make_tree(tmp_path)
    before = smoke.snapshot(tmp_path)
    assert set(before) == {
        "results/results.jsonl", "results/predictions/p.json", "frozen/v1/MANIFEST.md",
    }
    assert smoke.diff_snapshots(before, smoke.snapshot(tmp_path)) == {
        "added": [], "removed": [], "modified": [],
    }


def test_diff_detects_added_modified_and_removed_files(tmp_path):
    _make_tree(tmp_path)
    before = smoke.snapshot(tmp_path)
    (tmp_path / "results" / "new.json").write_text("x")
    (tmp_path / "results" / "results.jsonl").write_text("a\nb\n")
    (tmp_path / "frozen" / "v1" / "MANIFEST.md").unlink()
    assert smoke.diff_snapshots(before, smoke.snapshot(tmp_path)) == {
        "added": ["results/new.json"],
        "removed": ["frozen/v1/MANIFEST.md"],
        "modified": ["results/results.jsonl"],
    }


def test_diff_detects_a_same_size_content_change(tmp_path):
    _make_tree(tmp_path)
    before = smoke.snapshot(tmp_path)
    (tmp_path / "frozen" / "v1" / "MANIFEST.md").write_text("n")  # same length
    assert smoke.diff_snapshots(before, smoke.snapshot(tmp_path))["modified"] == [
        "frozen/v1/MANIFEST.md"
    ]


def test_snapshot_ignores_directories_that_do_not_exist(tmp_path):
    assert smoke.snapshot(tmp_path) == {}


def test_snapshot_only_covers_the_protected_directories(tmp_path):
    _make_tree(tmp_path)
    (tmp_path / "other.txt").write_text("x")
    assert all(k.startswith(("results/", "frozen/")) for k in smoke.snapshot(tmp_path))


def test_assert_outside_repo_refuses_paths_inside_the_repository(tmp_path):
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    for inside in (repo, repo / "sub", repo / "sub" / ".." / "sub"):
        with pytest.raises(smoke.IsolationError):
            smoke.assert_outside_repo(inside, repo)
    smoke.assert_outside_repo(tmp_path / "elsewhere", repo)  # no error


def test_prepare_sandbox_is_outside_the_repository_and_holds_only_inputs():
    sandbox = smoke.prepare_sandbox(ARCH)
    try:
        assert ROOT.resolve() not in sandbox.parents
        files = sorted(str(p.relative_to(sandbox)) for p in sandbox.rglob("*") if p.is_file())
        assert files == [
            f"benchmark/{ARCH}.ground_truth.json",
            f"benchmark/{ARCH}.json",
            "data/knowledge_base.json",
        ]
    finally:
        shutil.rmtree(sandbox)


# --- preflight ---------------------------------------------------------------------


def test_unreachable_ollama_raises_ollama_unavailable():
    with pytest.raises(smoke.OllamaUnavailable):
        smoke.ollama_models("http://127.0.0.1:1", timeout=1.0)


def test_ollama_models_parses_the_tags_response(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"models": [{"name": "llama3.1:8b"}, {"name": "x:latest"}]}).encode()

    seen = {}

    def fake_urlopen(url, timeout):
        seen["url"] = url
        return Response()

    monkeypatch.setattr(smoke.urllib.request, "urlopen", fake_urlopen)
    assert smoke.ollama_models("http://h:1/") == ["llama3.1:8b", "x:latest"]
    assert seen["url"] == "http://h:1/api/tags"


def test_non_json_answer_counts_as_unavailable(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"<html>not ollama</html>"

    monkeypatch.setattr(smoke.urllib.request, "urlopen", lambda url, timeout: Response())
    with pytest.raises(smoke.OllamaUnavailable):
        smoke.ollama_models("http://h:1")


def test_model_available():
    models = ["llama3.1:8b", "mistral:latest"]
    assert smoke.model_available(models, "llama3.1:8b")
    assert smoke.model_available(models, "mistral")  # bare name matches :latest
    assert not smoke.model_available(models, "llama3.1:70b")
    assert not smoke.model_available(models, "llama3.1")  # other tag is not a match
    assert not smoke.model_available([], "llama3.1:8b")


# --- environment for main ------------------------------------------------------------


def test_build_env_strips_inherited_controls_and_sets_the_run(monkeypatch):
    for name in smoke.CONTROLLED_ENV:
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("HOLDOUT", "1")
    monkeypatch.setenv("PYTHONPATH", "/inherited")

    env = smoke.build_env(["rag", "agent_pev_noplan"], ARCH, "m:1")

    assert env["ONLY"] == ARCH
    assert (env["TRACE"], env["RUNS"], env["OLLAMA_MODEL"]) == ("1", "1", "m:1")
    assert env["RAG"] == "1" and env["AGENT_PEV_NOPLAN"] == "1"
    # Everything not requested is gone, in particular the holdout switch.
    for name in ("AGENT", "AGENT_PEV", "AGENT_PEV_NOVERIFY", "AGENT_PEV_EXPLOREONLY", "HOLDOUT",
                 "AGENT_PEV_NODEEPEN", "AGENT_PEV_RICHDEEPEN", "AGENT_PEV_ADAPTIVEDEEPEN"):
        assert name not in env, name
    assert env["PYTHONPATH"].split(os.pathsep) == [str(ROOT), "/inherited"]
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"


def test_build_env_without_inherited_pythonpath(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    assert smoke.build_env(["rag"], ARCH, "m")["PYTHONPATH"] == str(ROOT)


# --- command line --------------------------------------------------------------------


def test_main_rejects_unknown_approach_and_architecture_before_any_network_call(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("must not contact Ollama")

    monkeypatch.setattr(smoke, "ollama_models", forbidden)
    assert smoke.main(["--approaches", "rag,nonsense"]) == smoke.EXIT_USAGE
    assert smoke.main(["--approaches", ""]) == smoke.EXIT_USAGE
    assert smoke.main(["--architecture", "does_not_exist"]) == smoke.EXIT_USAGE


def test_main_exit_codes_for_preflight(monkeypatch):
    def unavailable(host, timeout=5.0):
        raise smoke.OllamaUnavailable("down")

    monkeypatch.setattr(smoke, "ollama_models", unavailable)
    assert smoke.main(["--preflight-only"]) == smoke.EXIT_PREFLIGHT

    monkeypatch.setattr(smoke, "ollama_models", lambda host, timeout=5.0: ["other:1"])
    assert smoke.main(["--preflight-only"]) == smoke.EXIT_PREFLIGHT

    monkeypatch.setattr(smoke, "ollama_models", lambda host, timeout=5.0: ["llama3.1:8b"])
    called = []
    monkeypatch.setattr(smoke, "run_main", lambda *a, **k: called.append(a))
    assert smoke.main(["--preflight-only"]) == smoke.EXIT_OK
    assert called == [], "preflight-only must not run main"


def test_main_reports_a_violation_when_the_protected_directories_change(monkeypatch):
    """Simulate a run that modifies the repo's results/: the script must exit 3."""
    monkeypatch.setattr(smoke, "ollama_models", lambda host, timeout=5.0: ["llama3.1:8b"])
    snapshots = iter([{"results/a": "1:x"}, {"results/a": "1:y"}])
    monkeypatch.setattr(smoke, "snapshot", lambda root, names=None: next(snapshots))
    assert smoke.main(["--preflight-only"]) == smoke.EXIT_ISOLATION


def test_main_runs_main_in_a_sandbox_outside_the_repo(monkeypatch):
    """Everything but the subprocess is real; the subprocess is replaced by a recorder."""
    monkeypatch.setattr(smoke, "ollama_models", lambda host, timeout=5.0: ["llama3.1:8b"])
    seen = {}

    class Done:
        returncode = 0
        stdout = stderr = ""

    def fake_run(sandbox, env, timeout):
        seen["sandbox"], seen["env"] = sandbox, env
        return Done()

    monkeypatch.setattr(smoke, "run_main", fake_run)
    monkeypatch.setattr(smoke, "check_outputs", lambda *a, **k: ([], []))
    assert smoke.main([]) == smoke.EXIT_OK
    assert ROOT.resolve() not in seen["sandbox"].resolve().parents
    assert not seen["sandbox"].exists(), "sandbox is removed without --keep"
    assert seen["env"]["ONLY"] == smoke.DEFAULT_ARCHITECTURE


def test_main_exit_code_1_when_main_fails_and_when_checks_fail(monkeypatch):
    monkeypatch.setattr(smoke, "ollama_models", lambda host, timeout=5.0: ["llama3.1:8b"])

    class Failed:
        returncode = 1
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(smoke, "run_main", lambda *a, **k: Failed())
    assert smoke.main([]) == smoke.EXIT_CHECK_FAILED

    class Done:
        returncode = 0
        stdout = stderr = ""

    monkeypatch.setattr(smoke, "run_main", lambda *a, **k: Done())
    monkeypatch.setattr(smoke, "check_outputs", lambda *a, **k: (["bad"], []))
    assert smoke.main([]) == smoke.EXIT_CHECK_FAILED


# --- output checks against a sandbox produced by the real pipeline --------------------


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A sandbox filled by main.run_benchmark: deterministic baseline + stub PEV."""
    for suffix in (".json", ".ground_truth.json"):
        (tmp_path / "benchmark").mkdir(exist_ok=True)
        shutil.copy(ROOT / "benchmark" / f"{ARCH}{suffix}", tmp_path / "benchmark")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "TRACE", True)

    architecture = load_architecture(tmp_path / "benchmark" / f"{ARCH}.json")
    llm = gs.StubLLM(architecture)
    llm.model = "stub-model"
    retriever = KeywordRetriever(load_knowledge_base(ROOT / "data" / "knowledge_base.json"))
    main.run_benchmark(DeterministicThreatModeler(), ARCH, run_index=0)
    main.run_benchmark(StructuredAgentThreatModeler(llm=llm, retriever=retriever), ARCH,
                       run_index=0)
    return tmp_path


def _check(sandbox: Path, **overrides):
    kwargs = dict(approaches=["agent_pev"], architecture=ARCH, model="stub-model",
                  require_tokens=False)
    kwargs.update(overrides)
    return smoke.check_outputs(sandbox, **kwargs)


def _only_prediction_file(sandbox: Path) -> Path:
    rows = [json.loads(line)
            for line in (sandbox / "results" / "results.jsonl").read_text().splitlines()]
    row = next(r for r in rows if r["approach"] == "agent_pev")
    return sandbox / row["predictions_file"]


def _rewrite_predictions(path: Path, mutate) -> None:
    record = json.loads(path.read_text())
    mutate(record)
    path.chmod(path.stat().st_mode | stat.S_IWUSR)
    path.write_text(json.dumps(record))
    path.chmod(0o444)


def test_check_outputs_passes_on_a_real_pipeline_output(sandbox):
    failures, _ = _check(sandbox)
    assert failures == []


def test_check_outputs_flags_missing_results(tmp_path):
    failures, _ = smoke.check_outputs(tmp_path, ["rag"], ARCH, "m")
    assert failures and "results.jsonl" in failures[0]


def test_check_outputs_flags_an_approach_that_did_not_run(sandbox):
    failures, _ = _check(sandbox, approaches=["agent_pev", "rag"])
    assert any(f.startswith("rag: expected exactly one result row") for f in failures)


def test_check_outputs_flags_an_unexpected_approach(sandbox):
    failures, _ = _check(sandbox, approaches=[])
    assert any("agent_pev: unexpected approach ran" in f for f in failures)


def test_check_outputs_flags_a_wrong_model(sandbox):
    failures, _ = _check(sandbox, model="other-model")
    assert any("agent_pev: result row model" in f for f in failures)


def test_check_outputs_flags_a_tampered_description(sandbox):
    def blank(record):
        record["predictions"][0]["description"] = "  "

    _rewrite_predictions(_only_prediction_file(sandbox), blank)
    failures, _ = _check(sandbox)
    assert any("empty description or target" in f for f in failures)
    assert any("differ from the predictions" in f for f in failures)


def test_check_outputs_flags_a_prediction_count_mismatch(sandbox):
    def drop(record):
        record["predictions"].pop()

    _rewrite_predictions(_only_prediction_file(sandbox), drop)
    failures, _ = _check(sandbox)
    assert any("count differs" in f for f in failures)


def test_check_outputs_flags_a_writable_predictions_file(sandbox):
    path = _only_prediction_file(sandbox)
    path.chmod(0o644)
    failures, _ = _check(sandbox)
    assert any("writable" in f for f in failures)


def test_check_outputs_flags_a_missing_predictions_file(sandbox):
    path = _only_prediction_file(sandbox)
    path.chmod(0o644)
    path.unlink()
    failures, _ = _check(sandbox)
    assert any("predictions file missing" in f for f in failures)


def test_check_outputs_flags_candidate_texts_missing_from_the_trace(sandbox):
    (trace_file,) = (sandbox / "results" / "traces").glob("*.json")
    trace = json.loads(trace_file.read_text())
    del trace["elements"][0]["proposed_threats"]
    trace_file.write_text(json.dumps(trace))
    failures, _ = _check(sandbox)
    assert any("candidate texts missing" in f for f in failures)


def test_check_outputs_flags_trace_that_disagrees_with_the_predictions(sandbox):
    (trace_file,) = (sandbox / "results" / "traces").glob("*.json")
    trace = json.loads(trace_file.read_text())
    for element in trace["elements"]:
        if element["confirmed_threats"]:
            element["confirmed_threats"][0]["description"] += " (edited)"
            break
    else:
        pytest.skip("stub run confirmed no candidates")
    trace_file.write_text(json.dumps(trace))
    failures, _ = _check(sandbox)
    assert any("confirmed candidates in the trace differ" in f for f in failures)


def test_check_outputs_requires_token_usage_only_when_asked(sandbox):
    # The stub reports no tokens, like a client that does not expose usage.
    failures, _ = _check(sandbox, require_tokens=True)
    assert any("no token usage" in f for f in failures)
    failures, _ = _check(sandbox, require_tokens=False)
    assert not any("token" in f for f in failures)


def test_load_run_predictions_returns_fields_per_approach(sandbox):
    loaded = smoke.load_run_predictions(sandbox)
    assert set(loaded) == {"deterministic", "agent_pev"}
    assert all(len(item) == 4 for items in loaded.values() for item in items)
