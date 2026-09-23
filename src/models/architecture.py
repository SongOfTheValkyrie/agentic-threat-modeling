from typing import Any

from pydantic import BaseModel, Field


class Component(BaseModel):
    id: str
    name: str
    type: str
    technology: str | None = None
    internet_exposed: bool = False
    stores_sensitive_data: bool = False
    # Free-form configuration / posture state (e.g. {"public_access": true,
    # "logging_enabled": false, "iam_role": "admin"}). These states are not
    # captured by the boolean attributes above and typically require security
    # knowledge to interpret. The deterministic baseline ignores this field;
    # RAG and agentic approaches may read and reason over it.
    config: dict[str, Any] = Field(default_factory=dict)


class DataFlow(BaseModel):
    id: str
    source: str
    target: str
    protocol: str
    authenticated: bool = False
    encrypted: bool = False
    data_type: str | None = None


class TrustBoundary(BaseModel):
    id: str
    name: str
    component_ids: list[str]


class Architecture(BaseModel):
    id: str
    name: str
    components: list[Component]
    data_flows: list[DataFlow]
    trust_boundaries: list[TrustBoundary] = []