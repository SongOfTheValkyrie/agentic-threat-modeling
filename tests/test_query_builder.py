"""Tests for the fixed-query builder.

The builder turns an element's structured attributes and config into retrieval
terms. These tests pin down the term vocabulary: which attributes become terms,
how booleans vs. non-booleans in config are rendered, and that the "weakness,
not strength" convention holds for flows.
"""

from src.models.architecture import Component, DataFlow
from src.RAG.query_builder import (
    build_component_query,
    build_flow_query,
    build_queries,
)


def _terms(query: str) -> set[str]:
    return set(query.split())


def test_component_query_includes_type_and_posture_flags():
    comp = Component(
        id="web",
        name="Web",
        type="server",
        internet_exposed=True,
        stores_sensitive_data=True,
    )
    q = build_component_query(comp)

    assert q.target_id == "web"
    assert q.kind == "component"
    terms = _terms(q.query)
    assert "server" in terms
    assert "internet_exposed" in terms
    assert "stores_sensitive_data" in terms


def test_component_query_omits_flags_when_false():
    comp = Component(id="x", name="x", type="cache")
    terms = _terms(build_component_query(comp).query)

    assert "cache" in terms
    assert "internet_exposed" not in terms
    assert "stores_sensitive_data" not in terms


def test_config_boolean_emits_key_only():
    comp = Component(
        id="x",
        name="x",
        type="storage",
        config={"public_access": True, "logging_enabled": False},
    )
    terms = _terms(build_component_query(comp).query)

    # Keys are emitted regardless of true/false; the value is not appended.
    assert "public_access" in terms
    assert "logging_enabled" in terms
    assert "public_access_True" not in terms
    assert "logging_enabled_False" not in terms


def test_config_non_boolean_emits_key_and_key_value():
    comp = Component(
        id="x",
        name="x",
        type="storage",
        config={"iam_role": "admin"},
    )
    terms = _terms(build_component_query(comp).query)

    assert "iam_role" in terms
    assert "iam_role_admin" in terms


def test_flow_query_emits_weakness_terms():
    flow = DataFlow(
        id="f",
        source="a",
        target="b",
        protocol="TCP",
        authenticated=False,
        encrypted=False,
        data_type="pii",
    )
    q = build_flow_query(flow)

    assert q.target_id == "f"
    assert q.kind == "data_flow"
    terms = _terms(q.query)
    assert "data_flow" in terms
    assert "tcp" in terms  # protocol lowercased
    assert "unencrypted_flow" in terms
    assert "unauthenticated_flow" in terms
    assert "pii" in terms


def test_flow_query_omits_weakness_terms_when_secure():
    flow = DataFlow(
        id="f",
        source="a",
        target="b",
        protocol="HTTPS",
        authenticated=True,
        encrypted=True,
    )
    terms = _terms(build_flow_query(flow).query)

    assert "https" in terms
    assert "unencrypted_flow" not in terms
    assert "unauthenticated_flow" not in terms


def test_build_queries_covers_every_element_components_first(sample_architecture):
    queries = build_queries(sample_architecture)

    n_components = len(sample_architecture.components)
    n_flows = len(sample_architecture.data_flows)
    assert len(queries) == n_components + n_flows

    # Components are emitted before flows.
    assert all(q.kind == "component" for q in queries[:n_components])
    assert all(q.kind == "data_flow" for q in queries[n_components:])

    # Every element id is represented exactly once.
    target_ids = [q.target_id for q in queries]
    expected = [c.id for c in sample_architecture.components] + [
        f.id for f in sample_architecture.data_flows
    ]
    assert target_ids == expected
