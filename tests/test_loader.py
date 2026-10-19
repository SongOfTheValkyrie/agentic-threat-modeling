"""Tests for loading architectures and ground truth from disk.

These exercise the real benchmark files so a malformed or renamed file is
caught here rather than deep inside a run.
"""

from pathlib import Path

import pytest

from src.models.architecture import Architecture
from src.models.loader import load_architecture, load_ground_truth
from src.models.threat import Threat

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"

ARCHITECTURES = [
    "simple_web_api",
    "webapp_with_auth",
    "microservices_async",
    "cloud_ingest_pipeline",
    "multi_tenant_saas",
]


@pytest.mark.parametrize("name", ARCHITECTURES)
def test_load_architecture_parses_benchmark_files(name):
    arch = load_architecture(BENCHMARK_DIR / f"{name}.json")

    assert isinstance(arch, Architecture)
    assert arch.id
    assert arch.components  # every benchmark has at least one component


@pytest.mark.parametrize("name", ARCHITECTURES)
def test_load_ground_truth_parses_benchmark_files(name):
    threats = load_ground_truth(BENCHMARK_DIR / f"{name}.ground_truth.json")

    assert threats
    assert all(isinstance(t, Threat) for t in threats)
    # Each ground-truth threat must reference exactly one element so the
    # evaluator can key it.
    for t in threats:
        assert (t.component_id is None) != (t.data_flow_id is None)


def test_ground_truth_references_existing_elements():
    # Spot-check one architecture: every ground-truth target id must exist in
    # the architecture, otherwise the threat can never be matched.
    arch = load_architecture(BENCHMARK_DIR / "simple_web_api.json")
    threats = load_ground_truth(BENCHMARK_DIR / "simple_web_api.ground_truth.json")

    component_ids = {c.id for c in arch.components}
    flow_ids = {f.id for f in arch.data_flows}

    for t in threats:
        target = t.component_id or t.data_flow_id
        assert target in component_ids | flow_ids
