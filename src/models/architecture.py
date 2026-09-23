from pydantic import BaseModel


class Component(BaseModel):
    id: str
    name: str
    type: str
    technology: str | None = None
    internet_exposed: bool = False
    stores_sensitive_data: bool = False


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