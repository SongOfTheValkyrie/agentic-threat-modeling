"""Execution trace for the agent loop.

The agent decides its own actions each turn, so when it under-reports it is not
obvious *why*: did it finish early, loop on one element, skip components, or
emit unparseable JSON? The loop builds a message history internally and throws
it away. This module records a structured, step-by-step trace of what the agent
actually did (model output, parsed action, observation, and any control-flow
intervention) so a run can be inspected offline.

A trace is a pure data record: capturing one does not change the agent's
behaviour or its reported threats.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

DEFAULT_TRACE_DIR = "results/traces"


@runtime_checkable
class Traceable(Protocol):
    """Shared shape of a writable trace, so one writer serves every agent.

    The free-loop agent (AgentTrace) and the Plan-Explore-Verify agent
    (PevTrace) record very different structures, but both expose an
    architecture id, a model name, and a ``to_dict`` for serialization.
    """

    architecture: str
    model: str

    def to_dict(self) -> dict:
        ...


@dataclass
class StepRecord:
    """One turn of the agent loop.

    ``intervention`` records when the loop overrode the model rather than just
    executing its action, which is exactly where under-reporting hides:

    - ``"unparseable"``: the model output held no JSON action.
    - ``"loop"``: the model repeated its previous action; the loop redirected it.
    - ``"blocked_finish"``: the model tried to finish with elements still
      uninspected; the loop refused and nudged it onward.

    ``None`` means the action was executed normally.
    """

    step: int
    raw: str
    tool: str | None = None
    args: dict = field(default_factory=dict)
    observation: str | None = None
    intervention: str | None = None
    # Element ids inspected so far *after* this step (coverage over time).
    inspected: list[str] = field(default_factory=list)


@dataclass
class AgentTrace:
    """Full record of one agent run over one architecture."""

    architecture: str
    model: str
    steps: list[StepRecord] = field(default_factory=list)
    # Why the loop ended: "finished" (model finished with full coverage) or
    # "max_steps" (hit the step budget first — a strong under-reporting signal).
    outcome: str = "max_steps"
    num_reported: int = 0

    def add(self, record: StepRecord) -> None:
        self.steps.append(record)

    # --- derived diagnostics ---------------------------------------------

    def intervention_counts(self) -> dict[str, int]:
        """How many steps hit each kind of control-flow intervention."""
        counts: dict[str, int] = {}
        for s in self.steps:
            if s.intervention:
                counts[s.intervention] = counts.get(s.intervention, 0) + 1
        return counts

    def tool_counts(self) -> dict[str, int]:
        """How often each tool was invoked (executed steps only)."""
        counts: dict[str, int] = {}
        for s in self.steps:
            if s.tool and s.intervention is None:
                counts[s.tool] = counts.get(s.tool, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "architecture": self.architecture,
            "model": self.model,
            "outcome": self.outcome,
            "num_reported": self.num_reported,
            "num_steps": len(self.steps),
            "tool_counts": self.tool_counts(),
            "intervention_counts": self.intervention_counts(),
            "steps": [asdict(s) for s in self.steps],
        }


# ---------------------------------------------------------------------------
# Plan-Explore-Verify agent trace
# ---------------------------------------------------------------------------
#
# The PEV agent does not run one free loop; it runs a fixed pipeline (plan once,
# then explore+verify per element). Its diagnostic questions differ from the
# free agent's: did the plan prioritize anything? did prioritized elements
# actually trigger adaptive deepening? how many candidate threats did Explore
# propose per element, and how many survived Verify? A flat StepRecord list
# cannot express that, so PEV gets its own element-oriented record shape.


@dataclass
class DeepenStep:
    """One adaptive-deepening tool call during Explore (prioritized elements).

    ``tool`` is what the model asked for ("get_connections",
    "search_knowledge", or "done"/unknown which stops deepening); ``used``
    is False when the request was malformed or terminal, so the budget spent
    vs. usefully spent can be told apart.
    """

    tool: str | None
    args: dict = field(default_factory=dict)
    used: bool = True


@dataclass
class ElementRecord:
    """Explore + Verify for one architecture element.

    Captures the under-reporting signal at the element level: how many threats
    Explore proposed vs. how many Verify kept, and whether this element was
    prioritized enough to get adaptive deepening.
    """

    element_id: str
    kind: str  # "component" or "data_flow"
    prioritized: bool
    hypothesis: str = ""
    deepen_steps: list[DeepenStep] = field(default_factory=list)
    proposed: int = 0  # candidate threats from Explore
    confirmed: int = 0  # threats kept after Verify

    @property
    def dropped(self) -> int:
        """Candidates discarded by Verify (proposed minus confirmed)."""
        return max(self.proposed - self.confirmed, 0)


@dataclass
class PevTrace:
    """Full record of one Plan-Explore-Verify run over one architecture."""

    architecture: str
    model: str
    priorities: list[str] = field(default_factory=list)
    hypotheses: dict[str, str] = field(default_factory=dict)
    elements: list[ElementRecord] = field(default_factory=list)
    num_reported: int = 0

    def add_element(self, record: ElementRecord) -> None:
        self.elements.append(record)

    # --- derived diagnostics ---------------------------------------------

    def total_proposed(self) -> int:
        return sum(e.proposed for e in self.elements)

    def total_confirmed(self) -> int:
        return sum(e.confirmed for e in self.elements)

    def total_dropped(self) -> int:
        return sum(e.dropped for e in self.elements)

    def deepened_elements(self) -> list[str]:
        """Ids of elements that actually issued at least one deepening call."""
        return [e.element_id for e in self.elements if e.deepen_steps]

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "architecture": self.architecture,
            "model": self.model,
            "agent": "agent_pev",
            "priorities": self.priorities,
            "hypotheses": self.hypotheses,
            "num_reported": self.num_reported,
            "num_elements": len(self.elements),
            "totals": {
                "proposed": self.total_proposed(),
                "confirmed": self.total_confirmed(),
                "dropped": self.total_dropped(),
            },
            "deepened_elements": self.deepened_elements(),
            "elements": [
                {**asdict(e), "dropped": e.dropped} for e in self.elements
            ],
        }


def write_trace(trace: Traceable, directory: str | Path = DEFAULT_TRACE_DIR) -> Path:
    """Write one trace as a timestamped JSON file; returns the path written.

    One file per run (not appended) because a trace is large and read whole
    when diagnosing a single run, unlike the aggregate-friendly results log.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    # Model names like "ollama:llama3.1:8b" contain characters awkward in
    # filenames; keep the filename simple and portable.
    safe_model = trace.model.replace(":", "-").replace("/", "-")
    path = directory / f"{trace.architecture}_{safe_model}_{stamp}.json"
    with open(path, "w") as f:
        json.dump(trace.to_dict(), f, indent=2)
    return path
