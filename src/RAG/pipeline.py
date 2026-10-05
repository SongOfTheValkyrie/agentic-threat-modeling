import json
import re

from src.models.architecture import Architecture
from src.models.threat import StrideCategory, Threat
from src.RAG.knowledge import KnowledgeSnippet, load_knowledge_base
from src.RAG.llm import LLMClient
from src.RAG.query_builder import ElementQuery, build_queries
from src.RAG.retriever import KeywordRetriever, Retriever

SYSTEM_PROMPT = (
    "You are a security engineer performing STRIDE threat modeling. "
    "You analyze one element of a software architecture at a time and identify "
    "concrete, relevant threats. Use only the STRIDE categories: spoofing, "
    "tampering, repudiation, information_disclosure, denial_of_service, "
    "elevation_of_privilege. Do not invent threats for well-secured properties. "
    "Respond with JSON only, no prose."
)

# The model returns threats without a target id; we attach the element id
# ourselves so results map back onto the architecture deterministically.
_PROMPT_TEMPLATE = """\
Analyze this {kind} of a software architecture and list its security threats.

{kind} under analysis:
{element_json}

Relevant security knowledge (retrieved for context; use what applies, ignore \
what does not):
{knowledge}

Return a JSON object with a single key "threats" whose value is a list. Each \
item must have:
  - "category": one of spoofing, tampering, repudiation, \
information_disclosure, denial_of_service, elevation_of_privilege
  - "description": one sentence describing the threat
  - "mitigation": one sentence describing the mitigation

Only list threats that genuinely apply to this element. Return {{"threats": []}} \
if there are none. JSON only."""


def _format_knowledge(snippets: list[KnowledgeSnippet]) -> str:
    if not snippets:
        return "(no relevant knowledge retrieved)"
    return "\n".join(f"- [{s.source}] {s.title}: {s.text}" for s in snippets)


def _extract_json(raw: str) -> dict:
    """Pull a JSON object out of a model response.

    Models often wrap JSON in prose or code fences, so we locate the first
    balanced-looking object rather than trusting the whole string.
    """
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw

    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {"threats": []}

    try:
        return json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return {"threats": []}


def _element_payload(architecture: Architecture, query: ElementQuery) -> str:
    if query.kind == "component":
        element = next(c for c in architecture.components if c.id == query.target_id)
    else:
        element = next(f for f in architecture.data_flows if f.id == query.target_id)
    return element.model_dump_json(indent=2)


def _parse_threats(raw: str, query: ElementQuery) -> list[Threat]:
    data = _extract_json(raw)
    threats: list[Threat] = []

    for i, item in enumerate(data.get("threats", [])):
        category_raw = str(item.get("category", "")).strip().lower()
        try:
            category = StrideCategory(category_raw)
        except ValueError:
            # Skip anything the model emitted that is not a valid STRIDE value.
            continue

        description = str(item.get("description", "")).strip()
        if not description:
            continue

        threats.append(
            Threat(
                id=f"{query.target_id}_{category.value}_{i}",
                component_id=query.target_id if query.kind == "component" else None,
                data_flow_id=query.target_id if query.kind == "data_flow" else None,
                category=category,
                description=description,
                mitigation=str(item.get("mitigation", "")).strip(),
            )
        )

    return threats


class RagThreatModeler:
    """Fixed RAG workflow: retrieve knowledge per element, then ask the LLM.

    For each component and data flow it builds a fixed query, retrieves the
    top-k knowledge snippets, prompts the model with that one element plus the
    retrieved context, and parses the returned threats. The workflow is fixed:
    it does not decide what to investigate next (that is the agent's job).
    """

    name = "rag"

    def __init__(
        self,
        llm: LLMClient,
        retriever: Retriever | None = None,
        k: int = 4,
    ):
        self._llm = llm
        self._retriever = retriever or KeywordRetriever(load_knowledge_base())
        self._k = k

    def analyze(self, architecture: Architecture) -> list[Threat]:
        threats: list[Threat] = []

        for query in build_queries(architecture):
            snippets = self._retriever.retrieve(query.query, self._k)
            prompt = _PROMPT_TEMPLATE.format(
                kind=query.kind,
                element_json=_element_payload(architecture, query),
                knowledge=_format_knowledge(snippets),
            )
            raw = self._llm.complete(prompt, system=SYSTEM_PROMPT)
            threats.extend(_parse_threats(raw, query))

        return threats
