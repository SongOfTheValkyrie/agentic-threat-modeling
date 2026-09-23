import json
from pathlib import Path

from src.models.architecture import Architecture
from src.models.threat import Threat


def load_architecture(path: str | Path) -> Architecture:
    with open(path) as f:
        data = json.load(f)

    return Architecture.model_validate(data)


def load_ground_truth(path: str | Path) -> list[Threat]:
    with open(path) as f:
        data = json.load(f)

    return [Threat.model_validate(threat) for threat in data["threats"]]