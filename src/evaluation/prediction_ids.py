"""Stable, opaque identifiers for stored predictions (V2 annotation export).

A blinded annotation needs an identifier for each prediction that

* does not depend on the threat ``id`` the model or modeler assigned,
* does not depend on the order of an export or on a randomization of it,
* does not reveal the approach, model, or run to the annotator, and
* never changes, so labels can be joined back to the stored files later.

The identifier is a hash of what a prediction *is*: the identity of its run
(architecture, approach, model, run index, timestamp of the immutable file), its
position in that file, and its content (target, category, description,
mitigation). The threat ``id``, the derived ``key``, and the code version are not
part of it. The hash is one-way, so an exported identifier does not disclose the
approach, while the owner can recompute it from the stored file.

Position is part of the identity on purpose: two identical predictions in one run
are two predictions. Collapsing them into claims is a scoring step (V2_SPEC §7.3),
not an identifier concern.
"""

import hashlib
import json
from pathlib import Path

from src.evaluation.predictions import read_predictions

PREFIX = "pred-"
DIGEST_CHARS = 16


def prediction_uid(record: dict, index: int) -> str:
    """Identifier of ``record["predictions"][index]`` in a stored prediction record."""
    prediction = record["predictions"][index]
    payload = {
        "architecture": record["architecture"],
        "approach": record["approach"],
        "model": record["model"],
        "run_index": record["run_index"],
        "timestamp": record["timestamp"],
        "index": index,
        "target": prediction["target"],
        "category": prediction["category"],
        "description": prediction["description"],
        "mitigation": prediction["mitigation"],
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def prediction_uids(record: dict) -> list[str]:
    """Identifiers of all predictions of a record, in file order."""
    return [prediction_uid(record, i) for i in range(len(record["predictions"]))]


def uids_for_file(path: str | Path) -> list[str]:
    return prediction_uids(read_predictions(path))


def assert_unique(uids: list[str]) -> None:
    """Raise if identifiers collide, for example across the files of one export."""
    seen: set[str] = set()
    for uid in uids:
        if uid in seen:
            raise ValueError(f"duplicate prediction identifier {uid}")
        seen.add(uid)
