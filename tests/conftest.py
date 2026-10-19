"""Shared fixtures for the test suite.

All fixtures here are deterministic and offline: no Ollama server or network
access is required. The LLM-backed code paths are exercised through
``FakeLLMClient`` so tests stay fast and reproducible.
"""

import pytest

from src.models.architecture import Architecture, Component, DataFlow, TrustBoundary
from src.models.threat import Difficulty, StrideCategory, Threat


@pytest.fixture
def sample_architecture() -> Architecture:
    """A small architecture covering every deterministic rule branch.

    - ``web`` is internet-exposed (spoofing) and stores sensitive data
      (information disclosure).
    - ``db`` is internal, stores sensitive data (information disclosure only).
    - ``browser`` is an external entity and must be skipped by the rules.
    - ``flow_in`` is encrypted + authenticated (no flow threats).
    - ``flow_db`` is unencrypted + unauthenticated (both flow threats).
    """
    return Architecture(
        id="arch_test",
        name="Test Architecture",
        components=[
            Component(
                id="browser",
                name="User Browser",
                type="external_entity",
            ),
            Component(
                id="web",
                name="Web Server",
                type="server",
                internet_exposed=True,
                stores_sensitive_data=True,
                config={"public_access": True, "logging_enabled": False},
            ),
            Component(
                id="db",
                name="Database",
                type="database",
                internet_exposed=False,
                stores_sensitive_data=True,
                config={"iam_role": "admin"},
            ),
        ],
        data_flows=[
            DataFlow(
                id="flow_in",
                source="browser",
                target="web",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
                data_type="credentials",
            ),
            DataFlow(
                id="flow_db",
                source="web",
                target="db",
                protocol="TCP",
                authenticated=False,
                encrypted=False,
                data_type="pii",
            ),
        ],
        trust_boundaries=[
            TrustBoundary(id="tb", name="Internal", component_ids=["web", "db"]),
        ],
    )


@pytest.fixture
def ground_truth() -> list[Threat]:
    """A small ground-truth set spanning all three difficulty classes."""
    return [
        Threat(
            id="web_spoofing",
            component_id="web",
            category=StrideCategory.SPOOFING,
            description="Web server exposed to the internet.",
            mitigation="Require auth.",
            difficulty=Difficulty.EASY,
        ),
        Threat(
            id="flow_db_info",
            data_flow_id="flow_db",
            category=StrideCategory.INFORMATION_DISCLOSURE,
            description="Unencrypted internal flow.",
            mitigation="Encrypt in transit.",
            difficulty=Difficulty.MEDIUM,
        ),
        Threat(
            id="web_eop",
            component_id="web",
            category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            description="Public access on the web server bucket.",
            mitigation="Disable public access.",
            difficulty=Difficulty.HARD,
        ),
    ]
