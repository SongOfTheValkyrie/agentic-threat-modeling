from typing import Protocol, runtime_checkable

from src.models.architecture import Architecture
from src.models.threat import Threat


@runtime_checkable
class ThreatModeler(Protocol):
    """Common contract for every threat-modeling approach.

    Deterministic rules, the fixed RAG workflow, and the agent all differ
    internally, but each takes an architecture and returns a list of threats.
    Expressing that shared shape here lets the benchmark runner and evaluator
    treat all approaches identically, so comparisons differ only by approach.
    """

    name: str

    def analyze(self, architecture: Architecture) -> list[Threat]:
        """Produce threats for the given architecture."""
        ...
