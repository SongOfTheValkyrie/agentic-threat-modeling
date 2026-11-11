"""Offline tests for scripts/diagnostic_report.py.

The report states observations of one run: tool calls, deepening steps, the
termination decision per prioritized element, and cost. These tests build tiny
result directories by hand, so no model and no repository results are needed.
"""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCH = "multi_tenant_saas"
MODEL = "qwen2.5:7b"


def _load():
    spec = importlib.util.spec_from_file_location(
        "diagnostic_report", ROOT / "scripts" / "diagnostic_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report_mod = _load()


def _step(tool=None, args=None, success=False, reason=None, raw=""):
    return {
        "tool": tool, "args": args or {}, "tool_success": success,
        "termination_reason": reason, "raw_response": raw, "parsed_action": {},
    }


def _search(query):
    return _step("search_knowledge", {"query": query}, success=True)


def _element(element_id, steps, prioritized=True):
    return {
        "element_id": element_id, "kind": "component", "prioritized": prioritized,
        "hypothesis": "", "deepen_steps": steps,
    }


def _trace(approach, elements, priorities=("api", "shared_db")):
    return {
        "agent": approach, "architecture": ARCH, "priorities": list(priorities),
        "num_elements": len(elements), "elements": elements,
    }


def _row(approach, model=MODEL):
    return {
        "approach": approach, "architecture": ARCH, "model": model, "run_index": 0,
        "latency_seconds": 12.5, "llm_calls": 30, "tokens": 9000, "retrieval_calls": 11,
        "num_threats": 7, "f1": 0.5, "precision": 0.5, "recall": 0.5,
        "true_positives": 4, "false_positives": 4, "false_negatives": 4,
        "matched_keys": ["api:spoofing"], "missed_keys": ["db:tampering"],
    }


def _write(tmp_path, rows, traces):
    results = tmp_path / "results"
    (results / "traces").mkdir(parents=True)
    (results / "results.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    for i, trace in enumerate(traces):
        (results / "traces" / f"t{i}.json").write_text(json.dumps(trace))
    return results


def _build(results, approaches=("agent_pev",), model=MODEL):
    return report_mod.build_report(
        results, model=model, architecture=ARCH, approaches=list(approaches)
    )


def test_budget_exhausted_and_repeated_query_are_reported(tmp_path):
    elements = [
        _element("api", [_search("a"), _search("a"), _search("b"),
                         _step(reason="budget_exhausted")]),
        _element("shared_db", [_search("x"), _search("y"), _search("z"),
                               _step(reason="budget_exhausted")]),
    ]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    rep = _build(results)
    assert rep["problems"] == []
    obs = rep["approaches"][0]["deepening"]["observations"]
    per = {e["element_id"]: e for e in rep["approaches"][0]["deepening"]["per_element"]}
    assert per["api"]["final_termination"] == "budget_exhausted"
    assert per["api"]["tool_calls"] == 3
    assert per["api"]["repeated_identical_queries"] == 1
    assert per["shared_db"]["repeated_identical_queries"] == 0
    assert obs["same_termination_for_all_prioritized"] is True
    assert obs["element_dependent_behaviour"] is False
    assert obs["search_knowledge_only"] is True
    assert obs["get_connections_calls"] == 0
    assert obs["elements_with_repeated_identical_query"] == 1


def test_mixed_behaviour_across_elements_is_flagged(tmp_path):
    elements = [
        _element("api", [_step("done", reason="done")]),
        _element("shared_db", [
            _step("get_connections", {"component_id": "shared_db"}, success=True),
            _step("done", reason="done"),
        ]),
    ]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    obs = _build(results)["approaches"][0]["deepening"]["observations"]
    assert obs["element_dependent_behaviour"] is True
    assert obs["elements_with_done"] == 2
    assert obs["elements_with_tool_calls"] == 1
    assert obs["get_connections_calls"] == 1
    assert obs["search_knowledge_only"] is False


def test_failures_are_counted_and_raw_reply_is_kept_short(tmp_path):
    raw = "x" * 500
    elements = [
        _element("api", [_step(reason="invalid_json", raw=raw)]),
        _element("shared_db", [_step("teleport", reason="unknown_tool", raw="{}")]),
    ]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    rep = _build(results)["approaches"][0]["deepening"]
    assert rep["observations"]["invalid_json_steps"] == 1
    assert rep["observations"]["unknown_tool_steps"] == 1
    head = rep["per_element"][0]["steps"][0]["raw_response_head"]
    assert len(head) == report_mod.HEAD


def test_no_prioritized_elements_means_no_deepening_data(tmp_path):
    elements = [_element("api", [], prioritized=False)]
    results = _write(
        tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements, priorities=())]
    )
    obs = _build(results)["approaches"][0]["deepening"]["observations"]
    assert obs["prioritized_elements"] == 0
    assert obs["deepening_data_available"] is False
    assert obs["same_termination_for_all_prioritized"] is None
    assert obs["element_dependent_behaviour"] is None


def test_cost_fields_come_from_the_result_row(tmp_path):
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", [])])
    run = _build(results)["approaches"][0]["run"]
    assert (run["llm_calls"], run["tokens"], run["latency_seconds"]) == (30, 9000, 12.5)
    assert run["retrieval_calls"] == 11


def test_missing_cost_stays_null_not_zero(tmp_path):
    row = _row("agent_pev")
    del row["tokens"]
    results = _write(tmp_path, [row], [_trace("agent_pev", [])])
    assert _build(results)["approaches"][0]["run"]["tokens"] is None


def test_missing_row_and_trace_are_problems_not_crashes(tmp_path):
    results = _write(tmp_path, [], [])
    rep = _build(results, approaches=("agent_pev", "agent_pev_adaptivedeepen"))
    assert len(rep["problems"]) == 4  # a row and a trace missing for each approach
    assert report_mod.render_markdown(rep)  # still renders


def test_wrong_model_in_the_row_is_a_problem(tmp_path):
    results = _write(
        tmp_path, [_row("agent_pev", model="llama3.1:8b")], [_trace("agent_pev", [])]
    )
    problems = _build(results)["problems"]
    assert any("llama3.1:8b" in p and MODEL in p for p in problems)


def test_other_architectures_and_the_deterministic_row_are_ignored(tmp_path):
    other = _row("agent_pev")
    other["architecture"] = "simple_web_api"
    det = _row("deterministic", model="none")
    results = _write(tmp_path, [other, det, _row("agent_pev")], [_trace("agent_pev", [])])
    assert _build(results)["problems"] == []


def test_cli_writes_both_files_and_refuses_to_overwrite(tmp_path, capsys):
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", [])])
    out = tmp_path / "out"
    argv = ["--results-dir", str(results), "--out-dir", str(out), "--model", MODEL,
            "--architecture", ARCH, "--approaches", "agent_pev"]
    assert report_mod.main(argv) == 0
    assert (out / "diagnostic_report.json").exists()
    md = (out / "diagnostic_report.md").read_text()
    assert "no conclusion is drawn" in md
    assert report_mod.main(argv) == 4  # second call must not overwrite
    capsys.readouterr()


def test_report_draws_no_verdict_and_ranks_nothing(tmp_path):
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", [])])
    rep = _build(results)
    text = json.dumps(rep).lower() + report_mod.render_markdown(rep).lower()
    for word in ("supports", "capability limit", "conclusion: ", "winner", "better than"):
        assert word not in text
    assert "not used to rank models" in text


# --- fields added after the first Qwen run (post hoc) -------------------------------


def test_placeholder_argument_is_counted_and_separated_from_the_choice(tmp_path):
    """The shape seen with Qwen: search, then get_connections with the literal "<id>".
    The tool choice is identical for every element; only the outcome differs."""
    bad = [_search("q"), _step("get_connections", {"component_id": "<id>"}, reason="tool_error")]
    good = [_search("q"), _step("get_connections", {"component_id": "shared_db"}, success=True),
            _search("r"), _step(reason="budget_exhausted")]
    elements = [_element("api", bad), _element("shared_db", good)]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    obs = _build(results)["approaches"][0]["deepening"]["observations"]
    assert obs["element_dependent_behaviour"] is True  # the old, outcome-based indicator
    assert obs["tool_choice_same_over_common_prefix"] is True  # the choice is the same
    assert obs["placeholder_argument_steps"] == 1
    assert obs["attempted_tool_sequences"] == {
        "search_knowledge > get_connections": 1,
        "search_knowledge > get_connections > search_knowledge": 1,
    }


def test_different_tool_choices_are_still_detected(tmp_path):
    elements = [
        _element("api", [_search("q")]),
        _element(
            "shared_db",
            [_step("get_connections", {"component_id": "shared_db"}, success=True)],
        ),
    ]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    obs = _build(results)["approaches"][0]["deepening"]["observations"]
    assert obs["tool_choice_same_over_common_prefix"] is False


def test_failed_json_counts_as_an_attempted_step_not_a_tool(tmp_path):
    elements = [_element("api", [_step(reason="invalid_json", raw="oops")])]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", elements)])
    per = _build(results)["approaches"][0]["deepening"]["per_element"][0]
    assert per["attempted_tools"] == ["invalid_json"]
    assert per["placeholder_argument_steps"] == 0


def test_real_arguments_are_not_mistaken_for_placeholders(tmp_path):
    steps = [_step("search_knowledge", {"query": "a < b and c > d"}, success=True),
             _step("get_connections", {"component_id": "shared_db"}, success=True)]
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", [_element("api", steps)])])
    obs = _build(results)["approaches"][0]["deepening"]["observations"]
    assert obs["placeholder_argument_steps"] == 0


def test_post_hoc_fields_are_marked_as_such(tmp_path):
    results = _write(tmp_path, [_row("agent_pev")], [_trace("agent_pev", [])])
    rep = _build(results)
    assert set(rep["meta"]["post_hoc"]["fields"]) == {
        "attempted_tool_sequences", "tool_choice_same_over_common_prefix",
        "placeholder_argument_steps",
    }
    assert "Not part of the pre-registration" in rep["meta"]["post_hoc"]["note"]
