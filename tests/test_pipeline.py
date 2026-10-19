"""Tests for the fixed RAG pipeline.

The pipeline's risky parts are (1) pulling valid JSON out of a messy model
reply and (2) mapping that JSON onto Threat objects tied to the right element.
Both are exercised here with a FakeLLMClient and a stub retriever, so no Ollama
server or network is needed. One end-to-end test confirms the retrieve ->
prompt -> parse flow wires together.
"""

from src.models.threat import StrideCategory
from src.RAG.knowledge import KnowledgeSnippet
from src.RAG.llm import FakeLLMClient
from src.RAG.pipeline import RagThreatModeler, _extract_json, _parse_threats
from src.RAG.query_builder import ElementQuery


class StubRetriever:
    """Returns a fixed snippet list regardless of query, recording calls."""

    def __init__(self, snippets=None):
        self._snippets = snippets or []
        self.calls = 0

    def retrieve(self, query: str, k: int):
        self.calls += 1
        return self._snippets[:k]


# --- _extract_json --------------------------------------------------------


def test_extract_json_plain_object():
    assert _extract_json('{"threats": []}') == {"threats": []}


def test_extract_json_from_code_fence():
    raw = 'Here you go:\n```json\n{"threats": [{"category": "spoofing"}]}\n```'
    data = _extract_json(raw)
    assert data["threats"][0]["category"] == "spoofing"


def test_extract_json_with_surrounding_prose():
    raw = 'Sure! {"threats": []} Hope that helps.'
    assert _extract_json(raw) == {"threats": []}


def test_extract_json_returns_empty_on_garbage():
    assert _extract_json("no json here") == {"threats": []}
    assert _extract_json("{not valid json}") == {"threats": []}


# --- _parse_threats -------------------------------------------------------


def _component_query(target="web"):
    return ElementQuery(target_id=target, kind="component", query="server")


def _flow_query(target="flow_db"):
    return ElementQuery(target_id=target, kind="data_flow", query="data_flow")


def test_parse_threats_attaches_component_id():
    raw = '{"threats": [{"category": "spoofing", "description": "d", "mitigation": "m"}]}'
    threats = _parse_threats(raw, _component_query("web"))

    assert len(threats) == 1
    t = threats[0]
    assert t.component_id == "web"
    assert t.data_flow_id is None
    assert t.category == StrideCategory.SPOOFING
    assert t.description == "d"
    assert t.mitigation == "m"


def test_parse_threats_attaches_flow_id():
    raw = '{"threats": [{"category": "tampering", "description": "d"}]}'
    threats = _parse_threats(raw, _flow_query("flow_db"))

    assert threats[0].data_flow_id == "flow_db"
    assert threats[0].component_id is None


def test_parse_threats_skips_invalid_category():
    raw = '{"threats": [{"category": "nonsense", "description": "d"}]}'
    assert _parse_threats(raw, _component_query()) == []


def test_parse_threats_skips_empty_description():
    raw = '{"threats": [{"category": "spoofing", "description": "  "}]}'
    assert _parse_threats(raw, _component_query()) == []


def test_parse_threats_normalises_category_case_and_whitespace():
    raw = '{"threats": [{"category": "  SPOOFING ", "description": "d"}]}'
    threats = _parse_threats(raw, _component_query())
    assert threats[0].category == StrideCategory.SPOOFING


def test_parse_threats_empty_list():
    assert _parse_threats('{"threats": []}', _component_query()) == []


def test_parse_threats_generates_unique_ids():
    raw = (
        '{"threats": ['
        '{"category": "spoofing", "description": "a"},'
        '{"category": "spoofing", "description": "b"}'
        "]}"
    )
    threats = _parse_threats(raw, _component_query("web"))
    ids = [t.id for t in threats]
    assert len(set(ids)) == len(ids)


# --- end-to-end -----------------------------------------------------------


def test_analyze_runs_retrieve_prompt_parse(sample_architecture):
    # Every element yields one spoofing threat from the fake model.
    canned = '{"threats": [{"category": "spoofing", "description": "d", "mitigation": "m"}]}'
    llm = FakeLLMClient(response=canned)
    retriever = StubRetriever(
        snippets=[
            KnowledgeSnippet(
                id="k1",
                title="t",
                text="x",
                source="TEST",
            )
        ]
    )
    modeler = RagThreatModeler(llm=llm, retriever=retriever, k=4)

    threats = modeler.analyze(sample_architecture)

    n_elements = len(sample_architecture.components) + len(
        sample_architecture.data_flows
    )
    # One threat per element, one retrieval per element, one LLM call per element.
    assert len(threats) == n_elements
    assert retriever.calls == n_elements
    assert llm.llm_calls == n_elements
    # Retrieved knowledge is injected into the prompt.
    assert "TEST" in (llm.last_prompt or "")


def test_analyze_tolerates_empty_model_output(sample_architecture):
    modeler = RagThreatModeler(
        llm=FakeLLMClient(response="I could not find anything useful."),
        retriever=StubRetriever(),
    )
    assert modeler.analyze(sample_architecture) == []
