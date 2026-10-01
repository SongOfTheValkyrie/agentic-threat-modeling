from src.deterministic.rules import detect_threats
from src.models.architecture import Architecture
from src.models.threat import Threat


class DeterministicThreatModeler:
    """ThreatModeler adapter around the rule-based detector.

    Wraps the existing ``detect_threats`` function so the deterministic baseline
    satisfies the ThreatModeler contract without changing any rule logic.
    """

    name = "deterministic"

    def analyze(self, architecture: Architecture) -> list[Threat]:
        return detect_threats(architecture)
