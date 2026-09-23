import json
from pathlib import Path

from src.models.architecture import Architecture


def load_architecture(path: str | Path) -> Architecture:
    with open(path) as f:
        data = json.load(f)

    return Architecture.model_validate(data)