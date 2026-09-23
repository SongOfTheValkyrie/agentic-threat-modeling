from src.models.architecture import Architecture
from src.models.threat import StrideCategory, Threat


def detect_threats(architecture: Architecture) -> list[Threat]:
    threats = []

    for component in architecture.components:

        if component.internet_exposed:
            threats.append(
                Threat(
                    id=f"{component.id}_spoofing",
                    component_id=component.id,
                    category=StrideCategory.SPOOFING,
                    description=f"{component.name} is exposed to the internet.",
                    mitigation="Require strong authentication and authorization.",
                )
            )

        if component.stores_sensitive_data:
            threats.append(
                Threat(
                    id=f"{component.id}_information_disclosure",
                    component_id=component.id,
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    description=f"{component.name} stores sensitive data.",
                    mitigation="Encrypt sensitive data and restrict access.",
                )
            )

    for flow in architecture.data_flows:

        if not flow.encrypted:
            threats.append(
                Threat(
                    id=f"{flow.id}_information_disclosure",
                    data_flow_id=flow.id,
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    description=f"{flow.id} transmits data without encryption.",
                    mitigation="Encrypt data in transit.",
                )
            )

        if not flow.authenticated:
            threats.append(
                Threat(
                    id=f"{flow.id}_spoofing",
                    data_flow_id=flow.id,
                    category=StrideCategory.SPOOFING,
                    description=f"{flow.id} does not authenticate communication.",
                    mitigation="Authenticate communicating parties.",
                )
            )

    return threats