from enum import StrEnum

from pydantic import BaseModel


class StrideCategory(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Threat(BaseModel):
    id: str
    component_id: str | None = None
    data_flow_id: str | None = None
    category: StrideCategory
    description: str
    mitigation: str