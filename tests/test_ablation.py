"""Tests for the agent_pev ablation switches.

The ablation study disables one phase at a time to isolate its contribution.
These tests pin down the mechanics of each switch (via FakeLLMClient, no Ollama)
and that the default reproduces the unchanged baseline, so a measured difference
can be attributed to the switched-off phase rather than a coding accident.

Call order for the PEV pipeline (see test_trace_pev.py):
    1 plan call (skipped when use_plan=False),
    then per element: optional deepen calls (prioritized only),
                      1 explore call,
                      1 verify call (skipped when use_verify=False or no candidates).
"""

import json

from src.agent.structured import StructuredAgentThreatModeler
from src.RAG.llm import FakeLLMClient
from src.RAG.retriever import KeywordRetriever


def _agent(responses, **kwargs):
    return StructuredAgentThreatModeler(
        llm=FakeLLMClient(responses=responses),
        retriever=KeywordRetriever([]),
        **kwargs,
    )


def _plan(priorities=None, hypotheses=None):
    return json.dumps({"priorities": priorities or [], "hypotheses": hypotheses or {}})


def _threats(*categories):
    return json.dumps({
        "threats": [
            {"category": c, "description": f"desc {c}", "mitigation": "m"}
            for c in categories
        ]
    })


def _n(arch):
    return len(arch.components) + len(arch.data_flows)


# --- baseline is unchanged ------------------------------------------------


def test_default_variant_is_unchanged_baseline():
    agent = _agent([])
    assert agent.name == "agent_pev"


def test_baseline_llm_call_sequence_is_unchanged(sample_architecture):
    """Freeze the baseline's exact LLM-call sequence.

    The ablation switches must not alter the default pipeline. We record every
    prompt the baseline sends and assert the expected order and count for a run
    where the plan prioritizes one element that then deepens once:
    plan -> [per prioritized element: deepen turn(s), explore, verify]
         -> [per other element: explore (+ verify if it proposed candidates)].
    Also pins that the baseline deepen prompt stays the minimal one.
    """
    first = sample_architecture.components[0].id
    n = _n(sample_architecture)

    # Record each prompt the agent sends.
    class RecordingLLM(FakeLLMClient):
        def __init__(self, responses):
            super().__init__(responses=responses)
            self.prompts = []

        def chat(self, messages):
            # Record the user prompt (the deepen loop appends an assistant
            # "findings" turn after it, so take the last user message).
            user = next(
                (m["content"] for m in reversed(messages) if m["role"] == "user"),
                messages[-1]["content"],
            )
            self.prompts.append(user)
            return super().chat(messages)

    responses = [_plan(priorities=[first], hypotheses={first: "h"})]
    responses.append(json.dumps({"tool": "get_connections",
                                 "args": {"component_id": first}}))  # deepen
    responses.append(json.dumps({"tool": "done"}))                   # deepen stop
    responses.append(_threats("spoofing"))                           # explore first
    responses.append(_threats("spoofing"))                           # verify first
    for _ in range(n - 1):
        responses.append(_threats())  # explore only (no candidates -> no verify)

    llm = RecordingLLM(responses)
    agent = StructuredAgentThreatModeler(llm=llm, retriever=KeywordRetriever([]))
    agent.analyze(sample_architecture)

    # Call count: 1 plan + 2 deepen + 1 explore + 1 verify (first element)
    # + (n-1) explore for the rest = n + 4.
    assert len(llm.prompts) == n + 4
    # First call is the plan prompt.
    assert "review plan" in llm.prompts[0].lower()
    # The deepen prompt is the minimal baseline one (no element body).
    assert "{" not in llm.prompts[1] or "internet_exposed" not in llm.prompts[1]
    assert "additional investigation" in llm.prompts[1].lower()


def test_variant_names_reflect_disabled_phases():
    assert _agent([], use_plan=False).name == "agent_pev_noplan"
    assert _agent([], use_verify=False).name == "agent_pev_noverify"
    assert _agent([], use_deepening=False).name == "agent_pev_nodeepen"
    assert (
        _agent([], use_plan=False, use_verify=False).name
        == "agent_pev_noplan_noverify"
    )
    # An explicit label overrides the derived one.
    assert _agent([], variant="custom").name == "custom"


def test_no_deepening_keeps_plan_but_skips_deepening(sample_architecture):
    """use_deepening=False isolates deepening: the plan still runs (priorities
    and hypotheses present, elements still flagged prioritized) but no deepening
    tool call is made. This is the clean "no deepening" ablation that
    use_plan=False cannot provide."""
    first = sample_architecture.components[0].id
    n = _n(sample_architecture)

    # Plan prioritizes the first element. With deepening OFF, no deepen call is
    # consumed, so after the plan the responses are explore(/verify) per element.
    responses = [_plan(priorities=[first], hypotheses={first: "h"})]
    responses.append(_threats("spoofing"))  # explore first element
    responses.append(_threats("spoofing"))  # verify first element
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses, use_deepening=False)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.variant == "agent_pev_nodeepen"
    # Plan still ran: the element is prioritized and carries its hypothesis.
    rec = next(e for e in trace.elements if e.element_id == first)
    assert rec.prioritized is True
    assert rec.hypothesis == "h"
    # But no deepening happened anywhere.
    assert all(e.deepen_steps == [] for e in trace.elements)
    assert trace.deepened_elements() == []


# --- use_plan=False -------------------------------------------------------


def test_no_plan_skips_plan_call_and_prioritizes_nothing(sample_architecture):
    # With use_plan=False there is NO plan call: responses start at the first
    # element's explore call. Nothing is prioritized, so no deepening occurs.
    n = _n(sample_architecture)
    responses = [_threats() for _ in range(n)]  # one explore per element, no candidates

    agent = _agent(responses, use_plan=False)
    agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.variant == "agent_pev_noplan"
    assert trace.priorities == []
    assert trace.hypotheses == {}
    assert all(not e.prioritized for e in trace.elements)
    assert trace.deepened_elements() == []


def test_baseline_would_consume_a_plan_call(sample_architecture):
    # Mirror of the above: the baseline DOES make a plan call, so the same
    # explore-only script leaves the first element without an explore response.
    # This confirms the no-plan variant really skipped a call.
    n = _n(sample_architecture)
    # Baseline: first response is consumed by the plan call.
    responses = [_plan()] + [_threats() for _ in range(n)]

    agent = _agent(responses)  # baseline
    agent.analyze(sample_architecture)
    assert agent.last_trace.variant == "agent_pev"
    # Baseline recorded no priorities because the plan returned none.
    assert agent.last_trace.priorities == []


# --- use_verify=False -----------------------------------------------------


def test_no_verify_keeps_all_candidates(sample_architecture):
    # Explore proposes 2 on the first element; without verify all are kept.
    n = _n(sample_architecture)
    responses = [_plan()]
    responses.append(_threats("spoofing", "tampering"))  # explore: 2 candidates
    # No verify call follows, so the next responses are the remaining elements.
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses, use_verify=False)
    threats = agent.analyze(sample_architecture)
    trace = agent.last_trace

    assert trace.variant == "agent_pev_noverify"
    rec = trace.elements[0]
    assert rec.proposed == 2
    assert rec.confirmed == 2  # nothing dropped
    assert rec.dropped == 0
    assert trace.total_dropped() == 0
    assert len(threats) == 2


def test_verify_can_drop_in_baseline(sample_architecture):
    # Same explore output, but baseline runs verify which keeps only one.
    n = _n(sample_architecture)
    responses = [_plan()]
    responses.append(_threats("spoofing", "tampering"))  # explore: 2
    responses.append(_threats("spoofing"))               # verify: keep 1
    for _ in range(n - 1):
        responses.append(_threats())

    agent = _agent(responses)  # baseline
    threats = agent.analyze(sample_architecture)

    assert agent.last_trace.elements[0].confirmed == 1
    assert len(threats) == 1


# --- rich_deepen variant --------------------------------------------------


def _deepen_prompt_for(agent, kind, element_id, element_json, hypothesis, knowledge):
    return agent._deepen_prompt(
        kind, element_id, element_json, hypothesis, knowledge
    )


def test_rich_deepen_variant_name():
    assert _agent([], rich_deepen=True).name == "agent_pev_richdeepen"


def test_baseline_deepen_prompt_is_minimal():
    # The frozen baseline prompt must not leak the element body or hypothesis.
    agent = _agent([])  # rich_deepen=False
    prompt = _deepen_prompt_for(
        agent, "component", "api",
        element_json='{"id": "api", "internet_exposed": true}',
        hypothesis="check tenant isolation",
        knowledge="- [CWE-639] IDOR: ...",
    )
    assert "api" in prompt  # the id is there
    assert "internet_exposed" not in prompt  # but not the element body
    assert "check tenant isolation" not in prompt
    assert "CWE-639" not in prompt


def test_rich_deepen_prompt_includes_context():
    agent = _agent([], rich_deepen=True)
    prompt = _deepen_prompt_for(
        agent, "component", "api",
        element_json='{"id": "api", "internet_exposed": true}',
        hypothesis="check tenant isolation",
        knowledge="- [CWE-639] IDOR: ...",
    )
    # The rich prompt supplies the full element, hypothesis, and knowledge.
    assert "internet_exposed" in prompt
    assert "check tenant isolation" in prompt
    assert "CWE-639" in prompt


def test_rich_deepen_prompt_handles_empty_context():
    agent = _agent([], rich_deepen=True)
    prompt = _deepen_prompt_for(agent, "data_flow", "f1", "{}", "", "")
    # Empty hypothesis/knowledge render as explicit placeholders, not blanks.
    assert "(none)" in prompt
    assert "(none retrieved)" in prompt


# --- deepening conversation shape (regression) ----------------------------


def test_deepen_chat_ends_on_user_turn(sample_architecture):
    """Regression: the deepen call must not end on an assistant message.

    A trailing assistant turn leaves the model nothing to answer, so it returns
    an empty string that parses as no action -- which silently disabled all
    deepening. This records the message roles of every chat() call and asserts
    none ends with an assistant turn.
    """
    first = sample_architecture.components[0].id
    n = _n(sample_architecture)

    class RoleRecordingLLM(FakeLLMClient):
        def __init__(self, responses):
            super().__init__(responses=responses)
            self.last_roles = []

        def chat(self, messages):
            self.last_roles.append([m["role"] for m in messages])
            return super().chat(messages)

    # Prioritize the first element and have deepening issue two real tool calls
    # so the second turn carries prior findings (the case that used to append an
    # assistant message).
    responses = [_plan(priorities=[first])]
    responses.append(json.dumps({"tool": "get_connections",
                                  "args": {"component_id": first}}))
    responses.append(json.dumps({"tool": "get_connections",
                                  "args": {"component_id": first}}))
    responses.append(json.dumps({"tool": "done"}))
    responses.append(_threats("spoofing"))  # explore
    responses.append(_threats("spoofing"))  # verify
    for _ in range(n - 1):
        responses.append(_threats())

    llm = RoleRecordingLLM(responses)
    agent = StructuredAgentThreatModeler(llm=llm, retriever=KeywordRetriever([]))
    agent.analyze(sample_architecture)

    # No chat call may end on an assistant turn.
    assert all(roles[-1] != "assistant" for roles in llm.last_roles)
    # And the deepening did run real tool calls now (findings were threaded in).
    rec = next(e for e in agent.last_trace.elements if e.element_id == first)
    assert any(s.tool_success for s in rec.deepen_steps)
