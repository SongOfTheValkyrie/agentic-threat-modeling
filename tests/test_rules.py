"""Tests for the deterministic rule-based detector.

These rules are the baseline approach, so their behaviour must be pinned down
exactly: which attributes raise which STRIDE categories, and which components
are skipped as being outside the trust boundary.
"""

from src.deterministic.rules import EXTERNAL_COMPONENT_TYPES, detect_threats
from src.evaluation.evaluator import threat_key
from src.models.architecture import Architecture, Component, DataFlow
from src.models.threat import StrideCategory


def _keys(architecture: Architecture) -> set[tuple[str, str]]:
    return {threat_key(t) for t in detect_threats(architecture)}


def test_sample_architecture_produces_expected_threats(sample_architecture):
    keys = _keys(sample_architecture)

    # web: internet-exposed -> spoofing, sensitive -> info disclosure
    assert ("web", "spoofing") in keys
    assert ("web", "information_disclosure") in keys
    # db: internal + sensitive -> info disclosure only (no spoofing)
    assert ("db", "information_disclosure") in keys
    assert ("db", "spoofing") not in keys
    # flow_db: unencrypted -> info disclosure, unauthenticated -> spoofing
    assert ("flow_db", "information_disclosure") in keys
    assert ("flow_db", "spoofing") in keys
    # flow_in: encrypted + authenticated -> no flow threats
    assert ("flow_in", "information_disclosure") not in keys
    assert ("flow_in", "spoofing") not in keys


def test_external_components_are_skipped():
    # The browser is an external entity; no component-level threat is raised for
    # it even though every other condition could apply.
    arch = Architecture(
        id="a",
        name="a",
        components=[
            Component(
                id="ext",
                name="Third Party",
                type="external_service",
                internet_exposed=True,
                stores_sensitive_data=True,
            ),
        ],
        data_flows=[],
    )
    assert detect_threats(arch) == []


def test_every_external_type_is_recognised():
    # Guards the EXTERNAL_COMPONENT_TYPES set so a rename elsewhere is caught.
    for ext_type in EXTERNAL_COMPONENT_TYPES:
        arch = Architecture(
            id="a",
            name="a",
            components=[
                Component(
                    id="ext",
                    name="x",
                    type=ext_type,
                    internet_exposed=True,
                ),
            ],
            data_flows=[],
        )
        assert detect_threats(arch) == []


def test_config_field_is_ignored_by_deterministic_rules():
    # A dangerous config (public access, admin role) must not raise any threat:
    # reasoning over config is deliberately out of scope for the baseline.
    arch = Architecture(
        id="a",
        name="a",
        components=[
            Component(
                id="bucket",
                name="Bucket",
                type="storage",
                config={"public_access": True, "iam_role": "admin"},
            ),
        ],
        data_flows=[],
    )
    assert detect_threats(arch) == []


def test_secure_flow_raises_nothing():
    arch = Architecture(
        id="a",
        name="a",
        components=[],
        data_flows=[
            DataFlow(
                id="f",
                source="a",
                target="b",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
            ),
        ],
    )
    assert detect_threats(arch) == []


def test_threats_reference_valid_stride_categories(sample_architecture):
    for threat in detect_threats(sample_architecture):
        assert isinstance(threat.category, StrideCategory)
