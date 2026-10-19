"""Tests for the Plan-Explore-Verify agent trace (agent_pev).

The PEV agent runs a fixed pipeline, not a free loop, so its FakeLLMClient
responses must be scripted in exact call order:

    1 plan call,
    then per element (components first, then flows):
        if prioritized: up to 3 deepen calls (stops on "done"),
        1 explore call,
        1 verify call  (only when explore proposed >= 1 candidate).

These tests pin down that the trace records the plan, which elements deepened,
and the proposed-vs-confirmed counts that reveal where threats are dropped.
"""

import json

from src.agent.structured import StructuredAgentThreatModeler
from src.agent.trace import PevTrace, write_trace
from src.RAG.llm import FakeLLMClient
from src.RAG.retriever import KeywordRetriever


def _agent(responses: list[str]) -> StructuredAgentThreatModeler:
    return StructuredAgentThreatModeler(
        llm=FakeLLMClient(responses=responses),
        retriever=KeywordRetriever([]),
    )


def _plan(priorities=None, hypotheses=None) -> str:
    return json.dumps({
        "priorities": priorities or [],
        "hypotheses": hypotheses or {},
    })


def _threats(*categories: str) -> str:
    return json.dumps({
        "threats": [
            {"category": c, "description": f"desc {c}", "mitigation": "m"}
            for c in categories
        ]
    })


def _done() -> str:
    return json.dumps({"tool": "done"})


def _element_ids(arch):
    return [c.id for c in arch.components] + [f.id for f in arch.data_flows]


def test_trace_records_plan_and_per_element(sample_architecture):
    # No priorities -> no deepening for any element. Each element: explore then
    # (if candidates) verify. Here only the first element proposes a threat.
    n = len(_element_ids(sample_architecture))
    responses = [_plan()]  # plan: nothing prioritized
    for i in range(n):
        if i == 0:
            responses.append(_threats("spoofing"))  # explore proposes 1
            responses.append(_threats("spoofing"))  # verify keeps 1
        else:
            responses.append(_threats())  # explore proposes 0 -> no verify call

    agent = _agent(responses)
    threats = agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert isinstance(trace, PevTrace)
    assert trace.architecture == sample_architecture.id
    assert trace.priorities == []
    assert len(trace.elements) == n
    assert trace.num_reported == len(threats) == 1
    assert trace.total_proposed() == 1
    assert trace.total_confirmed() == 1
    # Nothing prioritized -> nothing deepened.
    assert trace.deepened_elements() == []


def test_trace_records_deepening_only_for_prioritized(sample_architecture):
    # Prioritize the first component and let it issue one get_connections call,
    # then "done". No other element deepens.
    first = sample_architecture.components[0].id
    n = len(_element_ids(sample_architecture))

    responses = [_plan(priorities=[first], hypotheses={first: "check it"})]
    # First element: deepen (get_connections on a valid id, then done), explore, verify.
    responses.append(json.dumps({
        "tool": "get_connections", "args": {"component_id": first}
    }))
    responses.append(_done())
    responses.append(_threats("spoofing"))  # explore
    responses.append(_threats("spoofing"))  # verify
    # Remaining elements: explore proposes nothing.
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.priorities == [first]
    assert trace.hypotheses.get(first) == "check it"
    assert trace.deepened_elements() == [first]

    rec = next(e for e in trace.elements if e.element_id == first)
    assert rec.prioritized is True
    # One real tool call (get_connections) plus the terminal "done" step.
    assert len(rec.deepen_steps) == 2
    assert rec.deepen_steps[0].tool == "get_connections"
    assert rec.deepen_steps[0].tool_success is True
    assert rec.deepen_steps[0].termination_reason is None
    # The terminal step is a deliberate "done", not a failure.
    assert rec.deepen_steps[-1].tool == "done"
    assert rec.deepen_steps[-1].tool_success is False
    assert rec.deepen_steps[-1].termination_reason == "done"


def test_deepening_invalid_json_is_not_counted_as_deepened(sample_architecture):
    # A prioritized element whose deepening reply is unparseable must NOT count
    # as deepened. This is the fix: "could not" explore differs from "would not".
    first = sample_architecture.components[0].id
    n = len(_element_ids(sample_architecture))

    responses = [_plan(priorities=[first])]
    responses.append("this is not json")          # deepen turn -> invalid_json
    responses.append(_threats("spoofing"))         # explore
    responses.append(_threats("spoofing"))         # verify
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    rec = next(e for e in trace.elements if e.element_id == first)
    assert rec.deepen_steps[0].termination_reason == "invalid_json"
    assert rec.deepen_steps[0].tool_success is False
    # Crucially: an aborted attempt does not make the element "deepened".
    assert trace.deepened_elements() == []


def test_deepening_unknown_tool_is_recorded(sample_architecture):
    first = sample_architecture.components[0].id
    n = len(_element_ids(sample_architecture))

    responses = [_plan(priorities=[first])]
    responses.append(json.dumps({"tool": "teleport"}))  # unknown tool
    responses.append(_threats("spoofing"))              # explore
    responses.append(_threats("spoofing"))              # verify
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    rec = next(e for e in trace.elements if e.element_id == first)
    assert rec.deepen_steps[0].termination_reason == "unknown_tool"
    assert rec.deepen_steps[0].tool == "teleport"
    assert trace.deepened_elements() == []


def test_trace_records_verify_dropping_candidates(sample_architecture):
    # Explore proposes two threats on the first element; verify keeps only one.
    # This is the key under-reporting signal: dropped = proposed - confirmed.
    n = len(_element_ids(sample_architecture))
    responses = [_plan()]
    responses.append(_threats("spoofing", "tampering"))  # explore: 2
    responses.append(_threats("spoofing"))               # verify: 1 kept
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    rec = trace.elements[0]
    assert rec.proposed == 2
    assert rec.confirmed == 1
    assert rec.dropped == 1
    assert trace.total_dropped() == 1


def test_trace_handles_empty_plan_gracefully(sample_architecture):
    # Plan returns unparseable text -> no priorities, pipeline still runs.
    n = len(_element_ids(sample_architecture))
    responses = ["not json"] + [_threats() for _ in range(n)]

    agent = _agent(responses)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.priorities == []
    assert trace.hypotheses == {}
    assert len(trace.elements) == n
    assert trace.total_proposed() == 0


def test_pev_trace_to_dict_is_json_serialisable(sample_architecture):
    n = len(_element_ids(sample_architecture))
    responses = [_plan()] + [_threats() for _ in range(n)]
    agent = _agent(responses)
    agent.analyze(sample_architecture)

    d = agent.last_trace.to_dict()
    restored = json.loads(json.dumps(d))
    assert restored["agent"] == "agent_pev"
    assert restored["num_elements"] == n
    assert "totals" in restored
    assert set(restored["totals"]) == {"proposed", "confirmed", "dropped"}
    # Each element dict carries the derived "dropped" field.
    assert all("dropped" in e for e in restored["elements"])


def test_write_trace_works_for_pev(tmp_path, sample_architecture):
    n = len(_element_ids(sample_architecture))
    responses = [_plan()] + [_threats() for _ in range(n)]
    agent = _agent(responses)
    agent.analyze(sample_architecture)

    path = write_trace(agent.last_trace, directory=tmp_path / "traces")
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["agent"] == "agent_pev"
    assert data["architecture"] == sample_architecture.id
