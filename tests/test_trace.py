"""Tests for agent execution traces.

These script a full agent run with FakeLLMClient(responses=[...]) and assert the
trace captures what the agent did, including the three control-flow
interventions (unparseable output, loop redirect, blocked premature finish)
that are the signatures of under-reporting. No Ollama server is needed.
"""

import json

from src.agent.modeler import AgentThreatModeler
from src.agent.trace import AgentTrace, StepRecord, write_trace
from src.RAG.llm import FakeLLMClient
from src.RAG.retriever import KeywordRetriever


def _agent(responses: list[str], max_steps: int = 40) -> AgentThreatModeler:
    # Empty knowledge base: search_knowledge returns "no knowledge", which is
    # fine — these tests exercise control flow and tracing, not retrieval.
    return AgentThreatModeler(
        llm=FakeLLMClient(responses=responses),
        retriever=KeywordRetriever([]),
        max_steps=max_steps,
    )


def _inspect_all(arch) -> list[str]:
    """Scripted actions that inspect every element, in order."""
    actions = []
    for c in arch.components:
        actions.append(json.dumps({
            "tool": "inspect_component", "args": {"component_id": c.id}
        }))
    for f in arch.data_flows:
        actions.append(json.dumps({
            "tool": "inspect_data_flow", "args": {"data_flow_id": f.id}
        }))
    return actions


# --- AgentTrace unit behaviour -------------------------------------------


def test_trace_counts_tools_and_interventions():
    trace = AgentTrace(architecture="a", model="fake")
    trace.add(StepRecord(step=0, raw="x", tool="inspect_component", args={}))
    trace.add(StepRecord(step=1, raw="x", tool="search_knowledge", args={}))
    trace.add(StepRecord(step=2, raw="x", tool="inspect_component",
                         intervention="loop"))
    trace.add(StepRecord(step=3, raw="x", intervention="unparseable"))

    # Intervened steps are excluded from tool_counts.
    assert trace.tool_counts() == {"inspect_component": 1, "search_knowledge": 1}
    assert trace.intervention_counts() == {"loop": 1, "unparseable": 1}


def test_trace_to_dict_is_json_serialisable():
    trace = AgentTrace(architecture="a", model="fake")
    trace.add(StepRecord(step=0, raw="x", tool="finish", observation="finish"))
    trace.outcome = "finished"
    trace.num_reported = 2

    d = trace.to_dict()
    # Round-trips through JSON without error.
    restored = json.loads(json.dumps(d))
    assert restored["outcome"] == "finished"
    assert restored["num_reported"] == 2
    assert restored["num_steps"] == 1
    assert restored["steps"][0]["tool"] == "finish"


# --- full agent run tracing ----------------------------------------------


def test_trace_records_full_run_and_finishes(sample_architecture):
    # Inspect every element, then report one threat, then finish.
    report = json.dumps({
        "tool": "report_threat",
        "args": {
            "target_id": "web", "category": "spoofing",
            "description": "exposed", "mitigation": "auth",
        },
    })
    finish = json.dumps({"tool": "finish"})
    responses = _inspect_all(sample_architecture) + [report, finish]

    agent = _agent(responses)
    threats = agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert len(threats) == 1
    assert trace.outcome == "finished"
    assert trace.num_reported == 1
    assert trace.architecture == sample_architecture.id
    # Coverage grows monotonically and ends covering every element.
    n_elements = len(sample_architecture.components) + len(
        sample_architecture.data_flows
    )
    assert len(trace.steps[-2].inspected) == n_elements  # before the finish step
    assert trace.tool_counts()["inspect_component"] == len(
        sample_architecture.components
    )


def test_trace_records_blocked_finish(sample_architecture):
    # Try to finish immediately (nothing inspected) -> blocked. Then inspect all
    # and finish for real.
    finish = json.dumps({"tool": "finish"})
    responses = [finish] + _inspect_all(sample_architecture) + [finish]

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.intervention_counts().get("blocked_finish") == 1
    assert trace.outcome == "finished"
    # The first step is the blocked finish with no coverage yet.
    assert trace.steps[0].intervention == "blocked_finish"
    assert trace.steps[0].inspected == []


def test_trace_records_loop_redirect(sample_architecture):
    # Same action twice in a row -> the second is a loop intervention.
    list_cmd = json.dumps({"tool": "list_components"})
    finish = json.dumps({"tool": "finish"})
    responses = (
        [list_cmd, list_cmd]  # second one triggers loop redirect
        + _inspect_all(sample_architecture)
        + [finish]
    )

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.intervention_counts().get("loop") == 1
    loop_steps = [s for s in trace.steps if s.intervention == "loop"]
    assert loop_steps[0].tool == "list_components"


def test_trace_records_unparseable_output(sample_architecture):
    garbage = "I am not JSON at all."
    finish = json.dumps({"tool": "finish"})
    responses = [garbage] + _inspect_all(sample_architecture) + [finish]

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.intervention_counts().get("unparseable") == 1
    assert trace.steps[0].intervention == "unparseable"
    assert trace.steps[0].tool is None


def test_trace_outcome_max_steps_when_budget_exhausted(sample_architecture):
    # Never inspects anything and never finishes successfully: the loop runs out
    # of steps. This is the clearest under-reporting signature.
    noop = json.dumps({"tool": "list_components"})
    agent = _agent([noop], max_steps=3)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.outcome == "max_steps"
    assert len(trace.steps) == 3
    assert trace.num_reported == 0


# --- writer ---------------------------------------------------------------


def test_write_trace_creates_json_file(tmp_path):
    trace = AgentTrace(architecture="simple_web_api", model="ollama:llama3.1:8b")
    trace.add(StepRecord(step=0, raw="x", tool="finish", observation="finish"))
    trace.outcome = "finished"

    path = write_trace(trace, directory=tmp_path / "traces")

    assert path.exists()
    # Model name's colons are sanitised out of the filename.
    assert ":" not in path.name
    data = json.loads(path.read_text())
    assert data["architecture"] == "simple_web_api"
    assert data["outcome"] == "finished"
