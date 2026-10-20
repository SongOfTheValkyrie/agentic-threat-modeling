"""StructuredAgentThreatModeler: a Plan-Explore-Verify agent variant.

Frozen design: see DESIGN_agent_pev.md. This hybrid workflow guarantees base
coverage (deterministic iteration over every element, mandatory knowledge
search per element) while allowing plan-driven adaptive deepening (bounded extra
tool calls). Candidate threats are verified per element/batch and merged
deterministically. It shares the same LLM, retriever, and knowledge base as
Fixed RAG, so what is tested is the orchestration, not access to new
information. The original AgentThreatModeler is left unchanged as a baseline.
"""

import json
import re

from src.agent.tools import ToolBox, ToolError
from src.agent.trace import DeepenStep, ElementRecord, PevTrace
from src.models.architecture import Architecture
from src.models.threat import StrideCategory, Threat
from src.RAG.knowledge import load_knowledge_base
from src.RAG.llm import LLMClient
from src.RAG.query_builder import build_component_query, build_flow_query
from src.RAG.retriever import KeywordRetriever, Retriever

STRIDE_VALUES = [c.value for c in StrideCategory]

MAX_ADAPTIVE_CALLS = 3  # per element, excluding the mandatory inspect + search

PLAN_SYSTEM = (
    "You are a security architect planning a STRIDE threat-modeling review. "
    "Given a list of components and data flows, you prioritize what matters. "
    "Respond with JSON only."
)

PLAN_PROMPT = """\
Here is the architecture to review:

{overview}

Produce a review plan as a JSON object:
{{
  "priorities": ["<component_id>", ...],          // security-critical elements
  "trust_boundaries": ["<short description>", ...],
  "hypotheses": {{"<element_id>": "<what to check>", ...}}
}}

Prioritize internet-facing components, data stores with sensitive data, shared
resources, and anything whose configuration looks risky. JSON only."""

EXPLORE_SYSTEM = (
    "You are a security engineer analyzing ONE element of an architecture. "
    "You are given the element, retrieved security knowledge, and optional "
    "extra findings. Propose concrete STRIDE threats that genuinely apply to "
    "this element. Respond with JSON only."
)

EXPLORE_PROMPT = """\
Element under analysis ({kind}):
{element_json}

Retrieved security knowledge:
{knowledge}
{extra}
Investigation hypothesis (may be empty): {hypothesis}

List the threats that genuinely apply to THIS element. Consider all six STRIDE
categories: {stride}. A single element often has several distinct threats.

Return JSON: {{"threats": [{{"category": "<stride>", "description": "<one \
sentence>", "mitigation": "<one sentence>"}}, ...]}}. Return {{"threats": []}} \
if none apply. JSON only."""

# The explore phase may also let the model request bounded extra tool calls.
# Baseline prompt: deliberately minimal — only the element id and type. Frozen;
# do not edit (the "rich" variant below is a separate experiment).
DEEPEN_PROMPT = """\
Element ({kind}): {element_id}. This element was flagged important in the plan.
You may request up to {budget} additional investigation step(s) to inform your
threat analysis, or none.

Available:
  {{"tool": "get_connections", "args": {{"component_id": "<id>"}}}}
  {{"tool": "search_knowledge", "args": {{"query": "<text>"}}}}
  {{"tool": "done"}}

Respond with a SINGLE JSON object (one tool, or done). JSON only."""

# Context-rich deepening prompt (experiment variant `agent_pev_richdeepen`).
# Hypothesis: the baseline prompt gives the model too little to decide whether
# extra investigation would help (just an id and type), which may explain why
# it almost always stops immediately. This variant additionally supplies the
# full element, the plan hypothesis, the knowledge already retrieved, and what
# each tool is for, so a decision to deepen (or not) is actually informed.
DEEPEN_PROMPT_RICH = """\
You are deciding whether to investigate this {kind} further before listing its
threats. It was prioritized in the plan, so extra investigation may be worth it.

Element under analysis:
{element_json}

Plan hypothesis to check (may be empty): {hypothesis}

Security knowledge already retrieved for it:
{knowledge}

You may request up to {budget} more investigation step(s), or stop now. Tools:
  {{"tool": "get_connections", "args": {{"component_id": "<id>"}}}}
      -> lists this component's data flows and components sharing a target,
         useful for trust-boundary and shared-resource threats.
  {{"tool": "search_knowledge", "args": {{"query": "<text>"}}}}
      -> retrieves more security knowledge for a specific concern not yet
         covered above.
  {{"tool": "done"}}
      -> stop investigating; the retrieved context is already sufficient.

Choose get_connections or search_knowledge only if it would reveal something the
context above does not already show. Respond with a SINGLE JSON object. JSON \
only."""

VERIFY_SYSTEM = (
    "You are a senior security reviewer validating proposed threats. For the "
    "given element, keep only threats that genuinely and specifically apply to "
    "it; discard vague, duplicate, or unjustified ones. Respond with JSON only."
)

VERIFY_PROMPT = """\
Element ({kind}):
{element_json}

Proposed threats for this element:
{candidates}

Return JSON with only the threats that genuinely apply:
{{"threats": [{{"category": "<stride>", "description": "...", \
"mitigation": "..."}}, ...]}}. Keep descriptions specific to this element. \
JSON only."""


def _extract_json(raw: str) -> dict:
    """Pull a JSON object out of a model response (fenced or bare)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        obj = json.loads(candidate[start : end + 1])
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        return {}


def _candidate_threats(data: dict) -> list[dict]:
    """Normalize a {"threats": [...]} payload into clean candidate dicts."""
    out = []
    for item in data.get("threats", []):
        if not isinstance(item, dict):
            continue
        category = str(item.get("category", "")).strip().lower()
        description = str(item.get("description", "")).strip()
        if category in STRIDE_VALUES and description:
            out.append({
                "category": category,
                "description": description,
                "mitigation": str(item.get("mitigation", "")).strip(),
            })
    return out


class StructuredAgentThreatModeler:
    """Plan-Explore-Verify agent (see DESIGN_agent_pev.md).

    Ablation switches isolate each phase's contribution. The defaults reproduce
    the frozen baseline exactly, so ``StructuredAgentThreatModeler(llm)`` is the
    unchanged ``agent_pev``. Turning a switch off yields a named variant:

    - ``use_plan=False``: skip the plan phase. With no priorities, no element is
      prioritized (so adaptive deepening never runs) and no hypotheses are
      injected into Explore. Tests whether planning improves detection.
    - ``use_verify=False``: skip the verify phase and keep every candidate
      Explore proposes. Tests whether Verify actually improves precision.
    - ``use_deepening=False``: skip only the adaptive deepening. Plan,
      prioritization, hypotheses, mandatory retrieval, Explore, and Verify are
      all unchanged. This isolates the contribution of the adaptive exploration
      itself, which ``use_plan=False`` cannot (it also removes prioritization
      and hypotheses).

    The ``variant`` name is used as the approach label in results and traces so
    ablation runs can be told apart; it defaults from the active switches.
    """

    def __init__(
        self,
        llm: LLMClient,
        retriever: Retriever | None = None,
        k: int = 4,
        use_plan: bool = True,
        use_verify: bool = True,
        use_deepening: bool = True,
        rich_deepen: bool = False,
        variant: str | None = None,
    ):
        self._llm = llm
        self._retriever = retriever or KeywordRetriever(load_knowledge_base())
        self._k = k
        self._use_plan = use_plan
        self._use_verify = use_verify
        # Adaptive deepening on prioritized elements. Off isolates its effect
        # while keeping every other phase identical to the baseline.
        self._use_deepening = use_deepening
        # When True, the deepening step uses the context-rich prompt instead of
        # the minimal baseline one (experiment: does more context make the model
        # actually investigate?). Baseline stays False.
        self._rich_deepen = rich_deepen
        self.name = variant or self._default_variant()

    def _default_variant(self) -> str:
        """Derive a label from the active switches (baseline -> 'agent_pev')."""
        if (
            self._use_plan
            and self._use_verify
            and self._use_deepening
            and not self._rich_deepen
        ):
            return "agent_pev"
        suffix = ""
        if not self._use_plan:
            suffix += "_noplan"
        if not self._use_verify:
            suffix += "_noverify"
        if not self._use_deepening:
            suffix += "_nodeepen"
        if self._rich_deepen:
            suffix += "_richdeepen"
        return "agent_pev" + suffix

    # --- Phase 1: Plan ----------------------------------------------------

    def _plan(self, architecture: Architecture, tool_box: ToolBox) -> dict:
        overview = tool_box.list_components()
        raw = self._llm.chat([
            {"role": "system", "content": PLAN_SYSTEM},
            {"role": "user", "content": PLAN_PROMPT.format(overview=overview)},
        ])
        plan = _extract_json(raw)
        return {
            "priorities": set(plan.get("priorities", []) or []),
            "hypotheses": plan.get("hypotheses", {}) or {},
        }

    # --- Phase 2: Explore (deterministic over all elements) ---------------

    def _deepen_prompt(
        self, kind: str, element_id: str, element_json: str,
        hypothesis: str, knowledge: str,
    ) -> str:
        """Build the deepening prompt for the active variant.

        The baseline uses the minimal prompt (id + type only); the rich variant
        adds the full element, plan hypothesis, and already-retrieved knowledge.
        """
        if self._rich_deepen:
            return DEEPEN_PROMPT_RICH.format(
                kind=kind, element_json=element_json,
                hypothesis=hypothesis or "(none)",
                knowledge=knowledge or "(none retrieved)",
                budget=MAX_ADAPTIVE_CALLS,
            )
        return DEEPEN_PROMPT.format(
            kind=kind, element_id=element_id, budget=MAX_ADAPTIVE_CALLS,
        )

    def _deepen(
        self,
        kind: str,
        element_id: str,
        tool_box: ToolBox,
        record: ElementRecord | None = None,
        element_json: str = "",
        hypothesis: str = "",
        knowledge: str = "",
    ) -> str:
        """Plan-driven adaptive deepening, bounded by MAX_ADAPTIVE_CALLS.

        If ``record`` is given, each deepening tool call is logged to it for
        tracing. Logging does not change which calls are made. The extra context
        args are only used by the rich-deepen prompt variant.
        """
        findings: list[str] = []
        prompt = self._deepen_prompt(
            kind, element_id, element_json, hypothesis, knowledge
        )

        def log(step: DeepenStep) -> None:
            if record is not None:
                record.deepen_steps.append(step)

        for _turn in range(MAX_ADAPTIVE_CALLS):
            # The chat must end on a user turn: a trailing assistant message
            # leaves the model nothing to answer and it returns an empty string
            # (which then parses as no action). So any findings so far are
            # appended to the user prompt instead of sent as an assistant turn.
            user_content = prompt
            if findings:
                user_content += "\n\nFindings so far:\n" + "\n".join(findings)
            raw = self._llm.chat([
                {"role": "system", "content": EXPLORE_SYSTEM},
                {"role": "user", "content": user_content},
            ])
            action = _extract_json(raw)
            tool = action.get("tool")
            args = action.get("args", {}) or {}

            # Classify the turn so the trace can tell "would not" from
            # "could not" explore (see DeepenStep). Only a tool that actually
            # runs and returns advances deepening; everything else terminates.
            if not action:
                log(DeepenStep(
                    tool=None, args={}, raw_response=raw, parsed_action={},
                    termination_reason="invalid_json",
                ))
                break
            if tool == "get_connections":
                try:
                    findings.append(
                        tool_box.get_connections(args.get("component_id", ""))
                    )
                    log(DeepenStep(
                        tool=tool, args=args, raw_response=raw,
                        parsed_action=action, tool_success=True,
                    ))
                except ToolError as exc:
                    findings.append(f"(error: {exc})")
                    log(DeepenStep(
                        tool=tool, args=args, raw_response=raw,
                        parsed_action=action, termination_reason="tool_error",
                    ))
                    break
            elif tool == "search_knowledge":
                q = str(args.get("query", "")).strip()
                if not q:
                    log(DeepenStep(
                        tool=tool, args=args, raw_response=raw,
                        parsed_action=action, termination_reason="tool_error",
                    ))
                    break
                findings.append(tool_box.search_knowledge(q))
                log(DeepenStep(
                    tool=tool, args=args, raw_response=raw,
                    parsed_action=action, tool_success=True,
                ))
            elif tool == "done":
                log(DeepenStep(
                    tool=tool, args=args, raw_response=raw,
                    parsed_action=action, termination_reason="done",
                ))
                break
            else:
                log(DeepenStep(
                    tool=tool, args=args, raw_response=raw,
                    parsed_action=action, termination_reason="unknown_tool",
                ))
                break
        else:
            # Loop completed without a terminating break: budget ran out while
            # the model was still issuing (successful) tool calls.
            log(DeepenStep(
                tool=None, args={}, termination_reason="budget_exhausted",
            ))

        return "\n".join(findings)

    def _explore_element(
        self, kind: str, element_id: str, element_json: str,
        query: str, hypothesis: str, prioritized: bool, tool_box: ToolBox,
        record: ElementRecord | None = None,
    ) -> list[dict]:
        # Mandatory knowledge search (same query logic as Fixed RAG).
        knowledge = tool_box.search_knowledge(query)

        # Plan-driven adaptive deepening only for prioritized elements, and only
        # when the deepening phase is enabled. The context args are ignored
        # unless the rich-deepen variant is active.
        extra = ""
        if prioritized and self._use_deepening:
            deep = self._deepen(
                kind, element_id, tool_box, record=record,
                element_json=element_json, hypothesis=hypothesis,
                knowledge=knowledge,
            )
            if deep:
                extra = f"\nAdditional findings:\n{deep}\n"

        raw = self._llm.chat([
            {"role": "system", "content": EXPLORE_SYSTEM},
            {"role": "user", "content": EXPLORE_PROMPT.format(
                kind=kind, element_json=element_json, knowledge=knowledge,
                extra=extra, hypothesis=hypothesis or "(none)",
                stride=", ".join(STRIDE_VALUES),
            )},
        ])
        return _candidate_threats(_extract_json(raw))

    # --- Phase 3+4: Verify per element, then deterministic merge ----------

    def _verify_element(
        self, kind: str, element_json: str, candidates: list[dict],
    ) -> list[dict]:
        if not candidates:
            return []
        raw = self._llm.chat([
            {"role": "system", "content": VERIFY_SYSTEM},
            {"role": "user", "content": VERIFY_PROMPT.format(
                kind=kind, element_json=element_json,
                candidates=json.dumps({"threats": candidates}, indent=2),
            )},
        ])
        return _candidate_threats(_extract_json(raw))

    # --- Orchestration ----------------------------------------------------

    def analyze(self, architecture: Architecture) -> list[Threat]:
        tool_box = ToolBox(architecture, self._retriever, k=self._k)
        self.last_tool_box = tool_box  # expose usage (retrieval_calls) to caller

        # Phase 1 (ablatable): without a plan there are no priorities or
        # hypotheses, so deepening never fires and Explore gets no hypothesis.
        if self._use_plan:
            plan = self._plan(architecture, tool_box)
            priorities = plan["priorities"]
            hypotheses = plan["hypotheses"]
        else:
            priorities = set()
            hypotheses = {}

        # Record the plan outcome and per-element explore/verify so the pipeline
        # can be inspected offline (see trace.py). Tracing does not change the
        # pipeline: each phase below just writes what it did into the record.
        model_name = getattr(self._llm, "name", "unknown")
        trace = PevTrace(
            architecture=architecture.id,
            model=model_name,
            variant=self.name,
            priorities=sorted(priorities),
            hypotheses={str(k): str(v) for k, v in hypotheses.items()},
        )
        self.last_trace = trace

        threats: list[Threat] = []
        index = 0

        # Deterministic iteration over every component, then every data flow.
        components = [(c.id, "component", c.model_dump_json(indent=2),
                       build_component_query(c).query) for c in architecture.components]
        flows = [(f.id, "data_flow", f.model_dump_json(indent=2),
                  build_flow_query(f).query) for f in architecture.data_flows]

        for element_id, kind, element_json, query in components + flows:
            prioritized = element_id in priorities
            hypothesis = str(hypotheses.get(element_id, "")).strip()

            record = ElementRecord(
                element_id=element_id,
                kind=kind,
                prioritized=prioritized,
                hypothesis=hypothesis,
            )

            candidates = self._explore_element(
                kind, element_id, element_json, query, hypothesis,
                prioritized, tool_box, record=record,
            )
            # Phase 3 (ablatable): without Verify, keep every proposed candidate.
            if self._use_verify:
                confirmed = self._verify_element(kind, element_json, candidates)
            else:
                confirmed = candidates

            record.proposed = len(candidates)
            record.confirmed = len(confirmed)
            trace.add_element(record)

            is_component = kind == "component"
            for t in confirmed:
                threats.append(Threat(
                    id=f"{element_id}_{t['category']}_{index}",
                    component_id=element_id if is_component else None,
                    data_flow_id=element_id if not is_component else None,
                    category=StrideCategory(t["category"]),
                    description=t["description"],
                    mitigation=t["mitigation"],
                ))
                index += 1

        trace.num_reported = len(threats)
        return threats
