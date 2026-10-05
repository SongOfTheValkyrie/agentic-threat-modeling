"""Tools the agent can call to explore an architecture and report threats.

Each tool is a plain, deterministic function over the architecture and the
knowledge base, so the whole toolset is testable without an LLM. The agent
loop decides which tool to call and with what arguments; this module only
executes them and returns a text observation (what the model sees next).

The toolset is intentionally exploratory: ``get_connections`` and
``search_knowledge`` let the model reason about component interactions and pull
knowledge on its own terms, which is the capability a fixed RAG workflow lacks.
"""

from src.models.architecture import Architecture
from src.models.threat import StrideCategory, Threat
from src.RAG.retriever import Retriever


class ToolError(Exception):
    """Raised when a tool is called with invalid arguments."""


class ToolBox:
    """Holds per-analysis state (architecture, retriever, reported threats).

    The agent reports threats via ``report_threat``; they accumulate in
    ``reported`` and are returned to the modeler at the end of the run.
    """

    def __init__(self, architecture: Architecture, retriever: Retriever, k: int = 4):
        self._arch = architecture
        self._retriever = retriever
        self._k = k
        self.reported: list[Threat] = []

    # --- exploration tools -------------------------------------------------

    def list_components(self) -> str:
        lines = ["Components (id: name [type]):"]
        for c in self._arch.components:
            lines.append(f"  {c.id}: {c.name} [{c.type}]")
        lines.append("Data flows (id: source -> target):")
        for f in self._arch.data_flows:
            lines.append(f"  {f.id}: {f.source} -> {f.target}")
        return "\n".join(lines)

    def inspect_component(self, component_id: str) -> str:
        for c in self._arch.components:
            if c.id == component_id:
                return c.model_dump_json(indent=2)
        raise ToolError(
            f"No component with id '{component_id}'. "
            f"Known ids: {[c.id for c in self._arch.components]}"
        )

    def inspect_data_flow(self, data_flow_id: str) -> str:
        for f in self._arch.data_flows:
            if f.id == data_flow_id:
                return f.model_dump_json(indent=2)
        raise ToolError(
            f"No data flow with id '{data_flow_id}'. "
            f"Known ids: {[f.id for f in self._arch.data_flows]}"
        )

    def get_connections(self, component_id: str) -> str:
        if not any(c.id == component_id for c in self._arch.components):
            raise ToolError(f"No component with id '{component_id}'.")

        incoming = [f for f in self._arch.data_flows if f.target == component_id]
        outgoing = [f for f in self._arch.data_flows if f.source == component_id]
        shared = [
            f
            for f in self._arch.data_flows
            if component_id in (f.source, f.target)
        ]
        # Who else connects to the same targets (useful for shared resources
        # like a cache or broker).
        peers = sorted(
            {
                other.source
                for f in shared
                for other in self._arch.data_flows
                if other.target == f.target and other.source != component_id
            }
        )

        lines = [f"Connections for '{component_id}':"]
        lines.append(f"  incoming: {[f.id for f in incoming]}")
        lines.append(f"  outgoing: {[f.id for f in outgoing]}")
        lines.append(f"  components sharing a target with it: {peers}")
        return "\n".join(lines)

    def search_knowledge(self, query: str) -> str:
        snippets = self._retriever.retrieve(query, self._k)
        if not snippets:
            return "No relevant knowledge found."
        return "\n".join(f"- [{s.source}] {s.title}: {s.text}" for s in snippets)

    # --- reporting tool ----------------------------------------------------

    def report_threat(
        self,
        target_id: str,
        category: str,
        description: str,
        mitigation: str = "",
    ) -> str:
        category_raw = str(category).strip().lower()
        try:
            stride = StrideCategory(category_raw)
        except ValueError as exc:
            raise ToolError(
                f"Invalid category '{category}'. Must be one of: "
                f"{[c.value for c in StrideCategory]}"
            ) from exc

        is_component = any(c.id == target_id for c in self._arch.components)
        is_flow = any(f.id == target_id for f in self._arch.data_flows)
        if not (is_component or is_flow):
            raise ToolError(f"Unknown target_id '{target_id}'.")

        if not str(description).strip():
            raise ToolError("A threat needs a non-empty description.")

        index = len(self.reported)
        self.reported.append(
            Threat(
                id=f"{target_id}_{stride.value}_{index}",
                component_id=target_id if is_component else None,
                data_flow_id=target_id if is_flow else None,
                category=stride,
                description=str(description).strip(),
                mitigation=str(mitigation).strip(),
            )
        )
        return f"Recorded threat: {stride.value} on {target_id}."
