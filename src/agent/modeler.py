"""Agentic threat modeler: prompt-based tool calling over an architecture.

Unlike the fixed RAG workflow, the model decides what to do each step. It is
given a toolset and a loop; at every turn it emits one JSON action (which tool
to call), we execute it, and feed the observation back. This lets it explore
component interactions and search knowledge on its own terms. The model, the
knowledge base, and the retriever are the same as RAG, so the only difference
under test is the agentic control flow itself.
"""

import json
import re

from src.agent.tools import ToolBox, ToolError
from src.models.architecture import Architecture
from src.models.threat import Threat
from src.RAG.knowledge import load_knowledge_base
from src.RAG.llm import LLMClient
from src.RAG.retriever import KeywordRetriever, Retriever

SYSTEM_PROMPT = """\
You are a security engineer doing STRIDE threat modeling of a software \
architecture by exploring it with tools.

Work one step at a time. On each step, respond with a SINGLE JSON object and \
nothing else, choosing one tool:

  {"tool": "list_components"}
  {"tool": "inspect_component", "args": {"component_id": "<id>"}}
  {"tool": "inspect_data_flow", "args": {"data_flow_id": "<id>"}}
  {"tool": "get_connections", "args": {"component_id": "<id>"}}
  {"tool": "search_knowledge", "args": {"query": "<text>"}}
  {"tool": "report_threat", "args": {"target_id": "<id>", "category": \
"<stride>", "description": "<one sentence>", "mitigation": "<one sentence>"}}
  {"tool": "finish"}

STRIDE categories: spoofing, tampering, repudiation, information_disclosure, \
denial_of_service, elevation_of_privilege.

Strategy: first list components, then inspect elements and their connections, \
search knowledge when useful, and report every genuine threat with \
report_threat. Pay attention to configuration and to resources shared between \
components. Only report threats that truly apply. Call finish when done.

Respond with JSON only."""

_DISPATCH = {
    "list_components": lambda tb, args: tb.list_components(),
    "inspect_component": lambda tb, args: tb.inspect_component(args["component_id"]),
    "inspect_data_flow": lambda tb, args: tb.inspect_data_flow(args["data_flow_id"]),
    "get_connections": lambda tb, args: tb.get_connections(args["component_id"]),
    "search_knowledge": lambda tb, args: tb.search_knowledge(args["query"]),
    "report_threat": lambda tb, args: tb.report_threat(
        target_id=args["target_id"],
        category=args["category"],
        description=args.get("description", ""),
        mitigation=args.get("mitigation", ""),
    ),
}


def _extract_action(raw: str) -> dict | None:
    """Pull one JSON action object out of a model response, or None."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        obj = json.loads(candidate[start : end + 1])
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _run_action(tool_box: ToolBox, action: dict) -> str:
    """Execute one parsed action and return the observation text."""
    tool = action.get("tool")
    args = action.get("args", {}) or {}

    if tool == "finish":
        return "finish"
    if tool not in _DISPATCH:
        return f"ERROR: unknown tool '{tool}'. Choose a valid tool."

    try:
        return _DISPATCH[tool](tool_box, args)
    except KeyError as exc:
        return f"ERROR: missing argument {exc} for tool '{tool}'."
    except ToolError as exc:
        return f"ERROR: {exc}"


class AgentThreatModeler:
    """Explores the architecture via tools and reports threats it finds."""

    name = "agent"

    def __init__(
        self,
        llm: LLMClient,
        retriever: Retriever | None = None,
        max_steps: int = 40,
        k: int = 4,
    ):
        self._llm = llm
        self._retriever = retriever or KeywordRetriever(load_knowledge_base())
        self._max_steps = max_steps
        self._k = k

    def _progress_hint(
        self, architecture: Architecture, inspected: set[str]
    ) -> str:
        """Tell the model which components it has not inspected yet.

        Small local models tend to lose track of what they have already done;
        a concrete reminder nudges them to cover every element before finishing.
        """
        remaining = [c.id for c in architecture.components if c.id not in inspected]
        if remaining:
            return f"Not yet inspected: {remaining}. Inspect them before finishing."
        return "All components inspected. Report remaining threats, then finish."

    def analyze(self, architecture: Architecture) -> list[Threat]:
        tool_box = ToolBox(architecture, self._retriever, k=self._k)

        transcript = (
            "Begin threat modeling. Start by calling list_components.\n"
        )
        inspected: set[str] = set()
        last_signature: str | None = None

        for _ in range(self._max_steps):
            raw = self._llm.complete(transcript, system=SYSTEM_PROMPT)
            action = _extract_action(raw)

            if action is None:
                transcript += (
                    "\nASSISTANT (unparsable): respond with a single JSON "
                    "action object only.\n"
                )
                continue

            # Loop detection: if the model repeats the exact same action, do not
            # re-run it; redirect it instead so it cannot spin in place.
            signature = json.dumps(action, sort_keys=True)
            if signature == last_signature:
                transcript += (
                    "\nNOTE: You just performed that exact action. Do something "
                    "different, inspect an uninspected element, or finish.\n"
                    f"{self._progress_hint(architecture, inspected)}\n"
                )
                last_signature = None  # allow the action again after redirect
                continue
            last_signature = signature

            observation = _run_action(tool_box, action)
            if observation == "finish":
                break

            if action.get("tool") == "inspect_component":
                comp_id = (action.get("args") or {}).get("component_id")
                if comp_id:
                    inspected.add(comp_id)

            # Append the chosen action and its observation so the model can
            # build on what it has already learned, plus a progress hint.
            transcript += (
                f"\nACTION: {json.dumps(action)}\n"
                f"OBSERVATION:\n{observation}\n"
                f"PROGRESS: {self._progress_hint(architecture, inspected)}\n"
            )

        return tool_box.reported
