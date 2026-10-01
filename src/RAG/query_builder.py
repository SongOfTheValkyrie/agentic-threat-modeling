from dataclasses import dataclass

from src.models.architecture import Architecture, Component, DataFlow


@dataclass
class ElementQuery:
    """A retrieval query tied to one architecture element.

    ``target_id`` is the component or data-flow id the query was built from, so
    retrieved knowledge can later be attributed back to the right element.
    """

    target_id: str
    kind: str  # "component" or "data_flow"
    query: str


def _config_terms(config: dict) -> list[str]:
    """Turn a component's config into retrieval terms.

    Keys are always emitted (e.g. ``public_access``). For boolean values we also
    emit the key when it is False, because a disabled control (encryption off,
    logging off) is itself the security signal. Non-boolean values are emitted
    as ``key_value`` (e.g. ``iam_role_admin``) so distinctive settings like an
    admin role become searchable terms.
    """
    terms: list[str] = []
    for key, value in config.items():
        terms.append(key)
        if isinstance(value, bool):
            # The key alone carries the signal regardless of true/false;
            # emitting it once is enough.
            continue
        terms.append(f"{key}_{value}")
    return terms


def build_component_query(component: Component) -> ElementQuery:
    terms: list[str] = [component.type]

    if component.internet_exposed:
        terms.append("internet_exposed")
    if component.stores_sensitive_data:
        terms.append("stores_sensitive_data")

    terms.extend(_config_terms(component.config))

    return ElementQuery(
        target_id=component.id,
        kind="component",
        query=" ".join(terms),
    )


def build_flow_query(flow: DataFlow) -> ElementQuery:
    terms: list[str] = ["data_flow", flow.protocol.lower()]

    # Emit the weakness, not the strength: an unencrypted / unauthenticated flow
    # is the security signal we want knowledge about.
    if not flow.encrypted:
        terms.append("unencrypted_flow")
    if not flow.authenticated:
        terms.append("unauthenticated_flow")
    if flow.data_type:
        terms.append(flow.data_type)

    return ElementQuery(
        target_id=flow.id,
        kind="data_flow",
        query=" ".join(terms),
    )


def build_queries(architecture: Architecture) -> list[ElementQuery]:
    """Build one fixed retrieval query per component and per data flow.

    This mapping is deliberately fixed: the fixed RAG workflow does not get to
    choose what to ask about (that would make it agentic). It always derives
    queries from every element's structured attributes and config.
    """
    queries = [build_component_query(c) for c in architecture.components]
    queries += [build_flow_query(f) for f in architecture.data_flows]
    return queries
