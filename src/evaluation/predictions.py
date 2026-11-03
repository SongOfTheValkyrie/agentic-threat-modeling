"""Persist the full predictions of every run (V2 logging, see V2_SPEC.md §6).

``results.jsonl`` stores only metrics and ``<target>:<category>`` keys. That is
enough for the V1 scheme but cannot support cause-level scoring, because the
threat descriptions are gone. This module stores what each approach actually
predicted, in order, with full text.

Logging is a pure side effect of a finished run: it reads the threats the
modeler already returned and does not influence them.

Each run gets its own file. Files are created exclusively (never overwritten)
and made read-only afterwards, so a prediction file is an immutable record that
later scoring runs can be pointed at.
"""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from src.evaluation.evaluator import threat_key
from src.models.threat import Threat

DEFAULT_PREDICTIONS_DIR = "results/predictions"
SCHEMA_VERSION = 1


def threat_to_dict(threat: Threat) -> dict:
    """One predicted threat as stored on disk.

    ``key`` is the V1 match key (``<target>:<category>``), kept next to the full
    text so both scoring schemes can read the same file.
    """
    target, category = threat_key(threat)
    return {
        "id": threat.id,
        "target": target,
        "target_kind": "component" if threat.component_id else "data_flow",
        "category": category,
        "description": threat.description,
        "mitigation": threat.mitigation,
        "key": f"{target}:{category}",
    }


def code_version() -> dict:
    """Git commit of the code that produced a run, and whether tracked files differ.

    Untracked files are ignored for the dirty flag: a stray script in the
    working tree does not change the code that ran. Failures (no git, not a
    repository) yield ``None`` values instead of breaking the run.
    """
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "dirty": None}
    return {"commit": commit, "dirty": dirty}


def write_predictions(
    *,
    approach: str,
    model: str,
    architecture: str,
    run_index: int,
    threats: list[Threat],
    directory: str | Path = DEFAULT_PREDICTIONS_DIR,
    code: dict | None = None,
) -> Path:
    """Write one run's predictions to a new read-only JSON file; return its path.

    Raises ``FileExistsError`` rather than overwriting an existing file.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    safe_model = model.replace(":", "-").replace("/", "-")
    filename = (
        f"{architecture}_{approach}_{safe_model}_run{run_index}_"
        f"{now.strftime('%Y%m%dT%H%M%S%f')}.json"
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": now.isoformat(),
        "approach": approach,
        "model": model,
        "architecture": architecture,
        "run_index": run_index,
        "code": code if code is not None else code_version(),
        "num_predictions": len(threats),
        "predictions": [threat_to_dict(t) for t in threats],
    }
    path = directory / filename
    with open(path, "x") as f:  # "x": fail instead of overwriting
        json.dump(record, f, indent=1, ensure_ascii=False)
        f.write("\n")
    path.chmod(0o444)
    return path


def read_predictions(path: str | Path) -> dict:
    """Load a prediction file written by :func:`write_predictions`."""
    return json.loads(Path(path).read_text())
